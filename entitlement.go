package tamga

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Entitlement is the `entitlements` JSON:API resource
// (Tamga API protocol specification §9). Despite the URL nesting under
// /licenses/{id}/entitlements, list/get on this endpoint return full
// Entitlement resources, not lightweight junction/relationship records.
type Entitlement struct {
	ID         string                `json:"id"`
	Type       string                `json:"type"`
	Attributes EntitlementAttributes `json:"attributes"`
}

// EntitlementKind distinguishes a boolean grant ("flag") from a named,
// per-license counter ("meter") — see EntitlementAttributes' doc comment.
// It is a plain string type rather than a closed Go enum, mirroring
// ValidationCode (validation.go) for the same reason: decoding an unknown
// value into a string never fails, so this SDK never hard-errors against a
// kind the server adds in the future.
//
// Unlike Inherited/MaxValue/CurrentValue below, Kind is always present on
// every response shape (account-, license-, policy-, and release-scoped
// alike) — it is a plain required field, never a pointer/omitted addition.
type EntitlementKind string

const (
	// EntitlementKindFlag is a boolean grant — the only kind that existed
	// before named metering. MaxValue/CurrentValue are present but not
	// enforced for it.
	EntitlementKindFlag EntitlementKind = "flag"
	// EntitlementKindMeter is a named, per-license counter with an
	// independent cap, tracked via IncrementEntitlementUsage/
	// DecrementEntitlementUsage/ResetEntitlementUsage. Fixed at creation —
	// there is no update path that turns one kind into the other.
	EntitlementKindMeter EntitlementKind = "meter"
)

// EntitlementAttributes is the attribute bag of an Entitlement resource.
//
// Code is the stable, developer-facing identifier — HasEntitlement matches
// on this field. Name is a display label only and may collide or change
// independently of Code; never match on it.
//
// Kind is always present — see EntitlementKind's doc comment.
//
// MaxValue and CurrentValue are meaningful only for Kind ==
// EntitlementKindMeter — present but not enforced for a flag. Like
// Inherited below, both are only present on the license-scoped list route
// (ListEntitlements/GetEntitlement); account-, policy-, and release-scoped
// responses omit them, which is why they are pointers: nil means "the
// server did not say", not "zero" or "unlimited".
//
//   - MaxValue is the effective cap — the license's own override if it has
//     one, else the policy's default, else nil for unlimited, the same
//     "nullable means unlimited" convention every other max_* field in
//     this package already uses.
//   - CurrentValue is the running count, 0 (not nil) when present but
//     never incremented. 0 does not necessarily mean "never used" — it
//     also means "only inherited from the license's policy, never
//     directly attached to this license", because only a direct
//     license_entitlements row carries a counter at all. Check Inherited
//     to tell the two apart.
//
// Inherited reports whether the license holds this entitlement through
// its policy rather than by a direct attachment. It is only present on
// the license-scoped list route (ListEntitlements) — account-, policy-,
// and release-scoped entitlement responses omit the field entirely, which
// is why it is a *bool: nil means "the server did not say", not false.
//
// It gates three things. An inherited entitlement cannot be detached from
// the license (403 POLICY_ENTITLEMENT). Attaching it directly on top is
// refused with 422 ENTITLEMENT_ALREADY_INHERITED — but only for Kind ==
// EntitlementKindFlag: a kind: "meter" entitlement CAN be attached
// directly even when already inherited via policy, because direct
// attachment is what creates the per-license counter row (MaxValue/
// CurrentValue) in the first place, not a redundant grant the way a
// second flag attachment would be. And GetEntitlement returns 404 for an
// inherited entitlement regardless of kind — see that method's doc
// comment.
type EntitlementAttributes struct {
	// Inherited, MaxValue, and CurrentValue lead the struct only to
	// satisfy govet's fieldalignment check; field order here carries no
	// wire meaning.
	Inherited    *bool           `json:"inherited,omitempty"`
	MaxValue     *int32          `json:"max_value,omitempty"`
	CurrentValue *int32          `json:"current_value,omitempty"`
	Name         string          `json:"name"`
	Code         string          `json:"code"`
	Kind         EntitlementKind `json:"kind"`
	Created      string          `json:"created"`
	Updated      string          `json:"updated"`
	Metadata     json.RawMessage `json:"metadata"`
}

// ListOptions is the shared keyset-pagination request shape used by
// ListComponents and ListEntitlements (Tamga API protocol specification
// §8/§9).
//
// Limit is clamped server-side to 1..100. Leaving it 0 does NOT mean
// "everything": the server silently falls back to 25 rows, and since
// these routes emit no page metadata and no links, a caller who did not
// pick a limit has no way to tell a complete answer from a truncated one.
// Both list methods therefore send an explicit limit of 100 (the server
// maximum) when Limit is unset, so the page size is always a known
// number.
//
// ⚠️ After works on ListComponents and is inert on ListEntitlements —
// see ListEntitlements' doc comment.
type ListOptions struct {
	After *string
	Limit int
}

// serverMaxPageLimit is the largest page size these keyset list routes
// accept, and the limit both list methods send when the caller did not
// choose one. See ListOptions.
const serverMaxPageLimit = 100

// effectivePageLimit is the page size a list call will actually request:
// the caller's Limit when they set one, otherwise serverMaxPageLimit
// rather than the server's silent 25-row default.
func effectivePageLimit(limit int) int {
	if limit > 0 {
		return limit
	}
	return serverMaxPageLimit
}

// EntitlementPage is a single page of ListEntitlements results.
//
// ⚠️ NextCursor on this type is always nil. It is retained so existing
// code compiles, but this route cannot be paginated — see
// ListEntitlements.
type EntitlementPage struct {
	NextCursor *string
	Items      []Entitlement
}

// ListEntitlements lists a license's entitlements.
// GET /v1/accounts/{account_id}/licenses/{license_id}/entitlements.
//
// ⚠️ This route is NOT paginated, despite accepting the keyset query
// parameters. The listing is a union of the license's direct entitlements
// and the ones inherited from its policy, which a single keyset cursor
// over one table cannot describe, so the server accepts page[after] for
// wire compatibility and then ignores it — the same first page comes back
// forever. A caller who loops "until the page is short" against this
// route never terminates.
//
// Consequently: ListEntitlements never sends page[after] (setting
// ListOptions.After has no effect here), and the returned
// EntitlementPage.NextCursor is unconditionally nil. limit is the only
// bound the server honors, capped at 100.
//
// The hard consequence is that a license with more than 100 effective
// entitlements cannot be enumerated in full through this endpoint at all.
// Treat a negative result — "this code is not in the list" — as
// authoritative only below that ceiling.
//
// ListComponents is a different story: keyset pagination genuinely works
// there, and its After is not inert.
func (c *Client) ListEntitlements(ctx context.Context, licenseID string, opts ListOptions) (*EntitlementPage, error) {
	path := fmt.Sprintf("/licenses/%s/entitlements", escapePathSegment(licenseID))
	query := url.Values{}
	query.Set("limit", strconv.Itoa(effectivePageLimit(opts.Limit)))
	fullPath := path + "?" + query.Encode()
	items, err := decodeJSONAPI[[]Entitlement](ctx, c, "GET", fullPath, nil)
	if err != nil {
		return nil, err
	}
	// NextCursor stays nil on purpose: handing back a cursor this route
	// ignores would invite exactly the loop that never terminates.
	return &EntitlementPage{Items: items}, nil
}

// GetEntitlement fetches a single entitlement by ID.
// GET /v1/accounts/{account_id}/licenses/{license_id}/entitlements/{entitlement_id}.
//
// ⚠️ Resolves DIRECT attachments only. The item route joins just the
// license_entitlements table, so an entitlement that ListEntitlements
// returned with Inherited true — held through the license's policy —
// comes back 404 NOT_FOUND here. List-then-get-each is not a valid
// pattern on this resource; read what you need off the list response.
func (c *Client) GetEntitlement(ctx context.Context, licenseID, entitlementID string) (*Entitlement, error) {
	path := fmt.Sprintf("/licenses/%s/entitlements/%s", escapePathSegment(licenseID), escapePathSegment(entitlementID))
	entitlement, err := decodeJSONAPI[Entitlement](ctx, c, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	return &entitlement, nil
}

// entitlementCacheTTL is how long HasEntitlement's per-license entitlement
// list cache stays fresh before the next call triggers a refetch.
const entitlementCacheTTL = 60 * time.Second

// entitlementCacheEntry holds one license's cached entitlement codes plus
// when the entry was fetched.
type entitlementCacheEntry struct {
	codes     map[string]struct{}
	fetchedAt time.Time
}

// entitlementCache is a simple in-memory TTL cache of per-license
// entitlement code sets, backing HasEntitlement. Safe for concurrent use.
//
// Entries are only evicted by TTL staleness (entitlementCacheTTL) on the
// next HasEntitlement call for that license, or explicitly via
// InvalidateEntitlementCache — there is no bounded-size/LRU eviction. This
// is a deliberate scope decision, not an oversight: this cache is keyed by
// license ID, and a single embedded/client SDK instance realistically
// validates a small, bounded number of distinct licenses over its
// lifetime (typically one — the license the host application itself is
// running under) — not an open-ended set driven by untrusted input where
// unbounded growth would be a real memory-exhaustion concern. If a future
// use case needs many distinct licenses tracked concurrently (e.g. a
// server-side integration validating licenses on behalf of many
// customers), add bounded eviction then; building it speculatively today
// would be complexity without a driving requirement.
type entitlementCache struct {
	entries map[string]entitlementCacheEntry
	mu      sync.Mutex
}

// entitlementCacheFor returns c's lazily-initialized entitlement cache.
// Client is constructed via New only, so this always starts nil; the
// lock-protected lazy-init pattern here avoids requiring New to always
// allocate a cache map even for callers who never use HasEntitlement.
func (c *Client) entitlementCacheFor() *entitlementCache {
	c.entCacheOnce.Do(func() {
		c.entCache = &entitlementCache{entries: make(map[string]entitlementCacheEntry)}
	})
	return c.entCache
}

// HasEntitlement reports whether licenseID's entitlement list contains an
// entitlement with the given code (the stable, developer-facing
// identifier) — matching on Code even when a different entitlement's Name
// happens to equal code, and never matching on Name itself.
//
// Backed by an in-memory TTL cache (entitlementCacheTTL) of the license's
// entitlement codes: a call within the TTL of a previous call for the same
// licenseID reuses the cached set instead of making a second HTTP call.
//
// ⚠️ Fetches exactly one page of 100 — the server's max — and that is the
// most this endpoint can ever return, because the route is not paginable
// (see ListEntitlements). A false result is therefore authoritative only
// for licenses holding at most 100 effective entitlements, counting
// policy-inherited ones. Above that ceiling a genuinely-held code can
// report false, and there is no server-side way to enumerate the rest.
// If your product issues more than 100 entitlements to a single license,
// do not gate features on this method.
func (c *Client) HasEntitlement(ctx context.Context, licenseID, code string) (bool, error) {
	cache := c.entitlementCacheFor()

	cache.mu.Lock()
	entry, ok := cache.entries[licenseID]
	fresh := ok && time.Since(entry.fetchedAt) < entitlementCacheTTL
	cache.mu.Unlock()

	if !fresh {
		page, err := c.ListEntitlements(ctx, licenseID, ListOptions{Limit: serverMaxPageLimit})
		if err != nil {
			return false, err
		}
		codes := make(map[string]struct{}, len(page.Items))
		for _, e := range page.Items {
			codes[e.Attributes.Code] = struct{}{}
		}
		entry = entitlementCacheEntry{codes: codes, fetchedAt: time.Now()}
		cache.mu.Lock()
		cache.entries[licenseID] = entry
		cache.mu.Unlock()
	}

	_, found := entry.codes[code]
	return found, nil
}

// InvalidateEntitlementCache drops the cached entitlement list for
// licenseID, forcing the next HasEntitlement call to refetch regardless of
// TTL — the explicit invalidation hatch for the in-memory cache
// HasEntitlement reads from.
func (c *Client) InvalidateEntitlementCache(licenseID string) {
	cache := c.entitlementCacheFor()
	cache.mu.Lock()
	delete(cache.entries, licenseID)
	cache.mu.Unlock()
}

// IncrementEntitlementUsage increments a kind: "meter" entitlement's
// CurrentValue on licenseID by increment, or by 1 (the server's own
// default) when increment is nil.
// POST /v1/accounts/{account_id}/licenses/{license_id}/entitlements/{entitlement_id}/actions/increment.
//
// Mirrors PingHeartbeat's shape one path segment deeper: no body is sent
// unless increment is set, and the response decodes back into the full
// Entitlement resource so the caller sees the fresh CurrentValue (and
// MaxValue) without a second round trip.
//
// increment is clamped to a minimum of 1 server-side — a zero or negative
// value is raised to 1, not rejected, the same rule the retired global
// counter's increment-usage action used.
//
// ⚠️ Requires the entitlement to be attached DIRECTLY to this license. One
// only inherited via the license's policy has no license_entitlements row
// to increment, and this call answers 404 NOT_FOUND
// (errors.Is(err, ErrNotFound)) until it is attached directly — see
// EntitlementAttributes' doc comment for the kind: "meter" exception that
// makes direct attachment possible even when the entitlement is already
// inherited.
//
// Fails with an error matching ErrMeterLimitExceeded (via errors.Is) when
// current_value + increment would exceed max_value. Read
// (*APIError).MeterEntitlementID to learn which entitlement hit its cap
// without re-parsing the request.
func (c *Client) IncrementEntitlementUsage(ctx context.Context, licenseID, entitlementID string, increment *int32) (*Entitlement, error) {
	path := fmt.Sprintf("/licenses/%s/entitlements/%s/actions/increment", escapePathSegment(licenseID), escapePathSegment(entitlementID))
	var body any
	if increment != nil {
		body = map[string]any{"increment": *increment}
	}
	entitlement, err := decodeJSONAPI[Entitlement](ctx, c, "POST", path, body)
	if err != nil {
		return nil, err
	}
	return &entitlement, nil
}

// DecrementEntitlementUsage decrements a kind: "meter" entitlement's
// CurrentValue on licenseID by decrement, or by 1 (the server's own
// default) when decrement is nil.
// POST /v1/accounts/{account_id}/licenses/{license_id}/entitlements/{entitlement_id}/actions/decrement.
// Same shape as IncrementEntitlementUsage — see its doc comment for the
// direct-attachment requirement.
//
// decrement is clamped to a minimum of 1 server-side, the same as
// increment. CurrentValue floors at 0 — it never goes negative, however
// large decrement is.
func (c *Client) DecrementEntitlementUsage(ctx context.Context, licenseID, entitlementID string, decrement *int32) (*Entitlement, error) {
	path := fmt.Sprintf("/licenses/%s/entitlements/%s/actions/decrement", escapePathSegment(licenseID), escapePathSegment(entitlementID))
	var body any
	if decrement != nil {
		body = map[string]any{"decrement": *decrement}
	}
	entitlement, err := decodeJSONAPI[Entitlement](ctx, c, "POST", path, body)
	if err != nil {
		return nil, err
	}
	return &entitlement, nil
}

// ResetEntitlementUsage rewinds a kind: "meter" entitlement's CurrentValue
// on licenseID back to 0.
// POST /v1/accounts/{account_id}/licenses/{license_id}/entitlements/{entitlement_id}/actions/reset,
// no body. Same direct-attachment requirement as IncrementEntitlementUsage
// — see its doc comment.
func (c *Client) ResetEntitlementUsage(ctx context.Context, licenseID, entitlementID string) (*Entitlement, error) {
	path := fmt.Sprintf("/licenses/%s/entitlements/%s/actions/reset", escapePathSegment(licenseID), escapePathSegment(entitlementID))
	entitlement, err := decodeJSONAPI[Entitlement](ctx, c, "POST", path, nil)
	if err != nil {
		return nil, err
	}
	return &entitlement, nil
}
