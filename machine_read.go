package tamga

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// PageMeta is the `meta.page` object an OFFSET-paginated collection
// returns. Exactly one route this SDK calls uses it: ListMachines.
//
// Everything else in this package is keyset-paginated with a synthetic
// cursor (ComponentPage.NextCursor, ProcessPage.NextCursor) or is not
// paginated at all (EntitlementPage). The machine collection genuinely
// disagrees with its own sub-collections — GET /machines/{id}/processes
// and GET /machines/{id}/components are keyset while GET /machines is
// offset — so do not try to unify the two shapes.
//
// TotalPages is the server's own ceiling division of Total by Size, and
// is 0 for an empty result rather than 1.
type PageMeta struct {
	Number     int `json:"number"`
	Size       int `json:"size"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
}

// pageMetaEnvelope decodes the `{"meta": {"page": {…}}}` wrapper the
// offset-paginated collections put PageMeta inside.
type pageMetaEnvelope struct {
	Page PageMeta `json:"page"`
}

// MachinePage is one page of ListMachines results plus the server's own
// page metadata.
//
// Unlike ComponentPage/ProcessPage there is no NextCursor: this route is
// offset-paginated and reports Page.TotalPages, so advance by asking for
// ListMachinesOptions.Page + 1 while Page.Number < Page.TotalPages.
type MachinePage struct {
	Items []Machine
	Page  PageMeta
}

// maxListMachinesOffset is the largest row offset the server will accept
// on an offset-paginated collection; a deeper page is refused with a 400
// PAGE_OUT_OF_RANGE rather than returning an empty page. Mirrored here so
// FindMachineByFingerprint stops walking before it provokes that error.
const maxListMachinesOffset = 100_000

// ListMachinesOptions filters and paginates ListMachines. Every field is
// optional; the zero value lists the first page of the account's machines
// newest-first.
//
// ⚠️ There is NO fingerprint filter. The server's ListMachinesFilters
// accepts filter[license], filter[owner], filter[group] and
// filter[platform] and nothing else. Query (filter[q]) is the only way to
// narrow by fingerprint, and it is a case-insensitive substring match
// across name, hostname AND fingerprint — not an equality test. Use
// FindMachineByFingerprint rather than hand-rolling that comparison.
//
// The four id/platform filters are comma-joined into ONE query value
// (filter[license]=a,b,c). A repeated key is not a list server-side: it
// silently collapses to its last occurrence, so this SDK never sends one.
// At most 50 values per filter, each at most 200 characters, or the
// server rejects the request with 400 INVALID_FILTER.
type ListMachinesOptions struct {
	// Query is the free-text filter[q] term: a case-insensitive '%term%'
	// match across name, hostname and fingerprint. Trimmed and truncated
	// to 200 characters server-side; a blank term is ignored entirely
	// rather than matching nothing.
	Query string
	// Sort names the column to order by. The server allows exactly
	// created_at, updated_at, name and last_heartbeat_at, and rejects
	// anything else with a 400 rather than falling back to the default.
	// A leading "-" means descending and a leading "+" ascending; bare
	// means descending, which is also what an unset Sort gives
	// (created_at, newest first).
	Sort string
	// LicenseIDs restricts the listing to these licenses (filter[license]).
	LicenseIDs []string
	// OwnerIDs restricts the listing to these owning users (filter[owner]).
	OwnerIDs []string
	// GroupIDs restricts the listing to these groups (filter[group]).
	GroupIDs []string
	// Platforms restricts the listing to these platform strings
	// (filter[platform]). Exact match, unlike Query.
	Platforms []string
	// Page is the 1-based page number (page[number]). Values below 1 are
	// raised to 1 server-side. Asking for a page whose row offset would
	// exceed 100,000 is a 400 PAGE_OUT_OF_RANGE — narrow with a filter
	// instead of paging that deep.
	Page int
	// PageSize is the rows per page (page[size]), clamped server-side to
	// 1..100. When unset this SDK sends 100 rather than letting the
	// server apply its 25-row default, matching ListComponents.
	PageSize int
}

// query renders the options as the wire query string ListMachines sends.
func (o ListMachinesOptions) query() url.Values {
	q := url.Values{}
	q.Set("page[size]", strconv.Itoa(effectivePageLimit(o.PageSize)))
	if o.Page > 0 {
		q.Set("page[number]", strconv.Itoa(o.Page))
	}
	if o.Sort != "" {
		q.Set("sort", o.Sort)
	}
	if o.Query != "" {
		q.Set("filter[q]", o.Query)
	}
	for name, values := range map[string][]string{
		"filter[license]":  o.LicenseIDs,
		"filter[owner]":    o.OwnerIDs,
		"filter[group]":    o.GroupIDs,
		"filter[platform]": o.Platforms,
	} {
		if len(values) > 0 {
			q.Set(name, strings.Join(values, ","))
		}
	}
	return q
}

// GetMachine reads one machine.
// GET /v1/accounts/{account_id}/machines/{id}.
//
// This is a read: the server resolves the row with find_by_id, which
// joins policies, so both HeartbeatStatus and NextHeartbeatAt on the
// returned Machine are computed against the policy's real
// heartbeat_duration rather than the 600s fallback the ping and
// reset-heartbeat routes land on. It is therefore the cheapest honest
// answer to "is this machine actually stale, and when is its next ping
// due" — see HeartbeatStatus.
//
// HeartbeatDead IS reachable here, unlike from PingHeartbeat. It still
// means only "the last ping is older than the window", never that the row
// was culled or the seat released; keep pinging through it.
func (c *Client) GetMachine(ctx context.Context, machineID string) (*Machine, error) {
	machine, err := decodeJSONAPI[Machine](ctx, c, "GET", fmt.Sprintf("/machines/%s", escapePathSegment(machineID)), nil)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// ListMachines lists the account's machines, OFFSET-paginated.
// GET /v1/accounts/{account_id}/machines.
//
// ⚠️ This is the one collection in this SDK that is not keyset-paginated.
// It returns meta.page{number,size,total,totalPages}, surfaced as
// MachinePage.Page; there is no cursor and MachinePage has no NextCursor
// field. Advance with ListMachinesOptions.Page while Page.Number <
// Page.TotalPages. Its own sub-collections (ListComponents,
// ListMachineProcesses) are keyset — that inconsistency is real server
// behaviour, not an SDK oversight.
//
// Like GetMachine this is a read, so HeartbeatStatus and NextHeartbeatAt
// are policy-derived on every item, and HeartbeatDead is reachable.
//
// ⚠️ Offset pagination is not stable under concurrent writes: a machine
// created or deleted between two page requests shifts every row after it,
// so a full walk can see a row twice or miss one. Narrow with a filter
// when that matters — see FindMachineByFingerprint, which does.
func (c *Client) ListMachines(ctx context.Context, opts ListMachinesOptions) (*MachinePage, error) {
	path := "/machines?" + opts.query().Encode()
	items, meta, err := decodeJSONAPIWithMeta[[]Machine, pageMetaEnvelope](ctx, c, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	return &MachinePage{Items: items, Page: meta.Page}, nil
}

// UpdateMachineOptions configures UpdateMachine. Every field is optional
// and a nil field is omitted from the request.
//
// ⚠️ An omitted field is left unchanged, and so is an explicitly null
// one: the server's UPDATE writes COALESCE($n, column) for all eight
// columns, so there is no way to clear a machine's name, ip, hostname or
// platform back to NULL through this route. Fingerprint and license are
// not updatable at all.
type UpdateMachineOptions struct {
	Name     *string
	IP       *string
	Hostname *string
	Platform *string
	Cores    *int32
	Memory   *int64 // megabytes, not bytes
	Disk     *int64 // megabytes, not bytes
	Metadata map[string]any
}

// attributes renders the non-nil fields as the request's attribute bag.
func (o UpdateMachineOptions) attributes() map[string]any {
	attrs := map[string]any{}
	if o.Name != nil {
		attrs["name"] = *o.Name
	}
	if o.IP != nil {
		attrs["ip"] = *o.IP
	}
	if o.Hostname != nil {
		attrs["hostname"] = *o.Hostname
	}
	if o.Platform != nil {
		attrs["platform"] = *o.Platform
	}
	if o.Cores != nil {
		attrs["cores"] = *o.Cores
	}
	if o.Memory != nil {
		attrs["memory"] = *o.Memory
	}
	if o.Disk != nil {
		attrs["disk"] = *o.Disk
	}
	if o.Metadata != nil {
		attrs["metadata"] = o.Metadata
	}
	return attrs
}

// UpdateMachine patches a machine's mutable attributes.
// PATCH /v1/accounts/{account_id}/machines/{id}.
//
// The request body is the full JSON:API envelope, like CreateMachine and
// unlike CreateComponent/CreateProcess.
//
// ⚠️ Memory and Disk are MEGABYTES here too — see MachineAttributes.
//
// ⚠️ The returned Machine's HeartbeatStatus and NextHeartbeatAt are NOT
// comparable with GetMachine's. PATCH is the one route that breaks the
// otherwise reliable write-versus-read split, in both directions at once:
//
//   - It never touches last_heartbeat_at, so it judges a timestamp it did
//     not write and CAN report HeartbeatDead — unlike PingHeartbeat,
//     ResetHeartbeat and CreateMachine, whose statuses are derived from
//     the stamp they just wrote.
//   - Its UPDATE … RETURNING does not join policies, so both fields are
//     computed against the 600s fallback whatever heartbeat_duration the
//     policy sets — unlike GetMachine and ListMachines, which do join.
//
// A GET and a PATCH of the same machine seconds apart can therefore
// disagree about both fields. Read them off GetMachine, never off this.
func (c *Client) UpdateMachine(ctx context.Context, machineID string, opts UpdateMachineOptions) (*Machine, error) {
	body := map[string]any{
		"data": map[string]any{
			"type":       "machines",
			"attributes": opts.attributes(),
		},
	}
	machine, err := decodeJSONAPI[Machine](ctx, c, "PATCH", fmt.Sprintf("/machines/%s", escapePathSegment(machineID)), body)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// FindMachineByFingerprint looks up a single already-registered machine
// on licenseID by its exact fingerprint, returning found = false when the
// license has no such machine.
//
// There is no fingerprint filter on GET /machines, so this is a two-step
// search and the two steps are not interchangeable:
//
//  1. Narrow server-side with filter[q], a case-insensitive '%term%'
//     match across name, hostname and fingerprint, scoped to
//     filter[license]=licenseID.
//  2. Compare Attributes.Fingerprint for exact, case-sensitive equality
//     client-side.
//
// Substring containment is a strict superset of equality, which is what
// makes the pair sound: step 1 can return machines this function then
// rejects, but it cannot hide one that equality would have matched. The
// same holds when the term is longer than the server's 200-character
// search bound, because a truncated prefix still contains-matches the
// full value.
//
// ⚠️ The search is deliberately scoped to the caller's own license, and
// widening it would be a bug rather than a courtesy. All three machine
// uniqueness strategies include the caller's own rows — UNIQUE_PER_LICENSE
// matches license_id directly, UNIQUE_PER_POLICY every license sharing the
// policy, UNIQUE_PER_ACCOUNT the whole account — so a genuine
// re-activation of this license's own machine is found under all three.
// Widening to the account adds exactly one case: the same fingerprint
// registered against a DIFFERENT license, which is the seat-sharing the
// wider strategies exist to refuse. A machine resource carries no
// license_id and no relationships object, so a caller handed such a row
// could never tell it had adopted another license's seat — it would ping
// and check out a machine its own license does not own while its
// machines_count stayed at zero. ActivateMachineIdempotent re-raises the
// 409 for that case instead of resolving it.
//
// The walk is bounded by the server's own meta.page.totalPages and stops
// before the 100,000-row offset ceiling that would 400. A blank
// fingerprint is refused locally rather than sent, since the server
// ignores a blank filter[q] and would answer with the license's entire
// machine list.
func (c *Client) FindMachineByFingerprint(ctx context.Context, licenseID, fingerprint string) (*Machine, bool, error) {
	if fingerprint == "" {
		return nil, false, fmt.Errorf("tamga: FindMachineByFingerprint requires a non-empty fingerprint")
	}
	opts := ListMachinesOptions{
		LicenseIDs: []string{licenseID},
		Query:      fingerprint,
		Page:       1,
	}
	for {
		page, err := c.ListMachines(ctx, opts)
		if err != nil {
			return nil, false, err
		}
		for i := range page.Items {
			if page.Items[i].Attributes.Fingerprint == fingerprint {
				return &page.Items[i], true, nil
			}
		}
		if page.Page.Number >= page.Page.TotalPages || len(page.Items) == 0 {
			return nil, false, nil
		}
		if page.Page.Number*page.Page.Size > maxListMachinesOffset {
			return nil, false, nil
		}
		opts.Page = page.Page.Number + 1
	}
}

// ActivateMachineIdempotent is ActivateMachine with the one exit the
// server leaves a client no way out of: a 409 FINGERPRINT_TAKEN.
//
// Re-registering a fingerprint that is already activated is refused
// (machines/service.rs checks uniqueness before the quota limits so that
// a re-activation reports FINGERPRINT_TAKEN rather than a misleading
// MACHINE_LIMIT_EXCEEDED), and the server offers no "create or return the
// existing one" mode. A client restarting on a machine it has already
// licensed therefore hits a hard error on a request that should be a
// no-op. This method turns that into an idempotent path: it looks the
// existing machine up with FindMachineByFingerprint and continues with
// the same validate step ActivateMachine performs.
//
// Behaviour differs from ActivateMachine in exactly two places, both on
// the recovery path:
//
//   - It returns the pre-existing machine rather than the error. If the
//     conflict cannot be resolved — because the fingerprint belongs to a
//     DIFFERENT license under UNIQUE_PER_POLICY or UNIQUE_PER_ACCOUNT,
//     and so is invisible to a license-scoped search — the original 409
//     is re-raised unchanged. Adopting that row would silently attach the
//     caller to a seat its license does not own; see
//     FindMachineByFingerprint.
//   - An over-limit verdict does NOT roll the machine back. ActivateMachine
//     deletes a machine it just created; this method did not create the
//     one it found, and deleting a machine that was already licensed would
//     destroy a working seat over a limit it is already inside. The
//     machine, the *ValidationMeta and an error matching ErrMachineOverLimit
//     are all returned, and the caller decides.
//
// Every other outcome is ActivateMachine's, unchanged: a create-time limit
// refusal short-circuits with a synthesized meta and no machine, a
// non-limit create error propagates as-is, and a successful create
// followed by an overage verdict still rolls back.
func (c *Client) ActivateMachineIdempotent(ctx context.Context, opts CreateMachineOptions, scope *Scope) (*Machine, *ValidationMeta, error) {
	machine, meta, err := c.ActivateMachine(ctx, opts, scope)
	if !errors.Is(err, ErrFingerprintTaken) {
		return machine, meta, err
	}

	existing, found, lookupErr := c.FindMachineByFingerprint(ctx, opts.LicenseID, opts.Fingerprint)
	if lookupErr != nil {
		return nil, nil, fmt.Errorf("tamga: re-activation lookup after %w failed: %w", err, lookupErr)
	}
	if !found {
		// The fingerprint is taken on another license under a wider
		// uniqueness strategy. Re-raise rather than resolve.
		return nil, nil, err
	}

	_, valMeta, valErr := c.ValidateByID(ctx, opts.LicenseID, &ValidateByIDOptions{Scope: scope})
	if valErr != nil {
		return existing, nil, valErr
	}
	if isOverageCode(valMeta.Code) {
		return existing, valMeta, fmt.Errorf("%w (code=%s)", ErrMachineOverLimit, valMeta.Code)
	}
	return existing, valMeta, nil
}
