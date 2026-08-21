package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Machine is the `machines` JSON:API resource (Tamga API protocol
// specification §5). Field set matches the server's actual
// MachineResource/MachineAttributes serializer — no relationships object,
// same as License.
type Machine struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Attributes MachineAttributes `json:"attributes"`
}

// MachineAttributes is the attribute bag of a Machine resource.
//
// ⚠️ Memory and Disk are MEGABYTES, not bytes. The server's `machines`
// table documents the unit on the column itself, and the same values feed
// the license's machines_memory_count/machines_disk_count aggregates that
// MEMORY_LIMIT_EXCEEDED/DISK_LIMIT_EXCEEDED are checked against. Reporting
// 16 GiB as 17179869184 rather than 16384 inflates those counters by a
// factor of 1048576 and trips the limit on the license's very next
// activation.
//
// NextHeartbeatAt is the server's own view of when the next ping is due:
// last_heartbeat_at plus the effective window. It is not a dependable read
// of the policy's window on every route — the ping and reset-heartbeat
// routes do not join the policy, so a PingHeartbeat response derives both
// NextHeartbeatAt and HeartbeatStatus from the 600s fallback whatever the
// policy says. See HeartbeatStatus's doc comment for the window itself.
type MachineAttributes struct {
	Platform        *string         `json:"platform"`
	NextHeartbeatAt *string         `json:"next_heartbeat_at"`
	Memory          *int64          `json:"memory"` // megabytes, not bytes
	Disk            *int64          `json:"disk"`   // megabytes, not bytes
	IP              *string         `json:"ip"`
	Hostname        *string         `json:"hostname"`
	Cores           *int32          `json:"cores"`
	LastCheckOutAt  *string         `json:"last_check_out_at"`
	Name            *string         `json:"name"`
	LastHeartbeatAt *string         `json:"last_heartbeat_at"`
	Fingerprint     string          `json:"fingerprint"`
	HeartbeatStatus HeartbeatStatus `json:"heartbeat_status"`
	Created         string          `json:"created"`
	Updated         string          `json:"updated"`
	Metadata        json.RawMessage `json:"metadata"`
}

// HeartbeatStatus is a machine's heartbeat state:
// NOT_STARTED -> ALIVE -> DEAD -> RESURRECTED. It is a plain string type,
// so an unrecognized wire value decodes cleanly rather than failing
// (forward-compatible with a future server-side addition).
//
// The window is policy-driven: the server judges a machine against its
// policy's heartbeat_duration when that field is set, and falls back to
// 600s (10 min) only when it is null.
//
// ⚠️ This SDK does not adapt to it. machineHeartbeatWindow — and so
// DefaultHeartbeatInterval, which is derived from it — is computed
// against the 600s fallback alone. On a policy that sets a shorter
// heartbeat_duration the default ping rate is too slow: the machine goes
// stale between ticks and reads DEAD. Such callers must pass their own
// interval to NewHeartbeatScheduler, and today they must learn their own
// window out of band — this SDK models the field as
// PolicyAttributes.HeartbeatDuration but exposes no call that returns a
// Policy.
//
// ⚠️ DEAD means ONLY "the last ping is older than the heartbeat window."
// It does NOT mean the machine row was culled, deleted, or deactivated,
// and it does not mean the seat was released. The server computes the
// status purely from last_heartbeat_at versus the window and never
// consults the policy's require_heartbeat flag, so a machine reports DEAD
// *forever* while its row — and its seat — are still there. Culling is a
// separate background job that early-returns for any policy with
// require_heartbeat = false, and that column defaults to FALSE: on a
// default policy nothing is ever culled, whatever HeartbeatCullStrategy
// says.
//
// DEAD is therefore neither terminal nor a reason to stop pinging.
// Client.PingHeartbeat against a DEAD machine succeeds and revives it —
// the server's update is a bare last_heartbeat_at = NOW() with no
// resurrection check gating it. Keep a HeartbeatScheduler running
// straight through a DEAD observation; stopping is what actually strands
// the machine.
//
// The only authoritative "this row is gone" signal is a 404 NOT_FOUND
// from the ping itself — errors.Is(err, ErrNotFound). Hang re-activation
// off that, never off a DEAD status.
type HeartbeatStatus string

// Heartbeat status constants — see HeartbeatStatus's doc comment for the
// state machine, and for why the window this is judged against is the
// policy's rather than the one this SDK schedules on.
const (
	HeartbeatNotStarted  HeartbeatStatus = "NOT_STARTED"
	HeartbeatAlive       HeartbeatStatus = "ALIVE"
	HeartbeatDead        HeartbeatStatus = "DEAD"
	HeartbeatResurrected HeartbeatStatus = "RESURRECTED"
)

// machineHeartbeatWindow is the server's 600-second (10 min) *fallback*
// machine heartbeat window, which applies only to a policy that leaves
// heartbeat_duration null. It is a constant here because this SDK cannot
// read the policy, so a shorter policy-configured window is not reflected
// — see HeartbeatStatus's doc comment.
const machineHeartbeatWindow = 600 * time.Second

// CreateMachineOptions configures CreateMachine. Fingerprint and LicenseID
// are required; every other field is optional.
//
// ⚠️ Memory and Disk are MEGABYTES, not bytes — see MachineAttributes'
// doc comment for why reporting bytes here corrupts the license's
// memory/disk counters permanently.
type CreateMachineOptions struct {
	Name        *string
	IP          *string
	Hostname    *string
	Platform    *string
	Cores       *int32
	Memory      *int64 // megabytes, not bytes
	Disk        *int64 // megabytes, not bytes
	Metadata    map[string]any
	Fingerprint string
	LicenseID   string
}

// CreateMachine registers a machine against a license.
// POST /v1/accounts/{account_id}/machines.
//
// Unique per (account_id, license_id, fingerprint) — a duplicate
// fingerprint on the same license fails with an error matching
// ErrFingerprintTaken (via errors.Is).
//
// Machine/core/memory/disk limits ARE checked at creation time: the
// server refuses with a 422 carrying MACHINE_LIMIT_EXCEEDED,
// CORE_LIMIT_EXCEEDED, MEMORY_LIMIT_EXCEEDED, or DISK_LIMIT_EXCEEDED
// (match with errors.Is against ErrMachineLimitExceeded and friends).
// That check runs through the policy's overage strategy, exactly like the
// one validation runs — so it is NOT a guarantee that a successfully
// created machine is inside its limits. Under ALLOW_1_25X_OVERAGE (or
// any of the other permissive strategies) creation succeeds past the
// nominal max and the overage only surfaces later, as a TOO_MANY_*/
// TOO_MUCH_* ValidationCode from ValidateByID.
//
// Both paths therefore have to be handled to implement "reject
// over-limit activation" — see ActivateMachine, which does exactly that
// and normalizes the two vocabularies onto one error.
//
// The uniqueness pre-check runs BEFORE the limit checks, so a
// re-activation of an already-registered fingerprint reports
// FINGERPRINT_TAKEN rather than a misleading limit error.
func (c *Client) CreateMachine(ctx context.Context, opts CreateMachineOptions) (*Machine, error) {
	metadata := opts.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "machines",
			"attributes": map[string]any{
				"fingerprint": opts.Fingerprint,
				"name":        opts.Name,
				"ip":          opts.IP,
				"hostname":    opts.Hostname,
				"platform":    opts.Platform,
				"cores":       opts.Cores,
				"memory":      opts.Memory,
				"disk":        opts.Disk,
				"metadata":    metadata,
			},
			"relationships": map[string]any{
				"license": map[string]any{
					"data": map[string]any{"type": "licenses", "id": opts.LicenseID},
				},
			},
		},
	}
	machine, err := decodeJSONAPI[Machine](ctx, c, "POST", "/machines", body)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// DeleteMachine deletes a machine. DELETE /v1/accounts/{account_id}/machines/{id}.
func (c *Client) DeleteMachine(ctx context.Context, machineID string) error {
	return doNoContent(ctx, c, "DELETE", fmt.Sprintf("/machines/%s", escapePathSegment(machineID)))
}

// isOverageCode reports whether code is one of the over-limit
// ValidationCode outcomes ActivateMachine's rollback-delete path reacts to.
func isOverageCode(code ValidationCode) bool {
	switch code {
	case ValidationCodeTooManyMachines, ValidationCodeTooManyCores,
		ValidationCodeTooMuchMemory, ValidationCodeTooMuchDisk,
		ValidationCodeTooManyProcesses:
		return true
	default:
		return false
	}
}

// createTimeLimitCode maps a create-time 422 error code
// (MACHINE_LIMIT_EXCEEDED and friends, raised by POST /machines before
// any row is written) onto the equivalent ValidationCode that the same
// limit would produce from a validate call.
//
// The two vocabularies exist because the checks live in different server
// modules, but they describe the same four limits. Normalizing here is
// what lets ActivateMachine hand every caller a single *ValidationMeta
// shape regardless of which code path caught the overage — a caller
// switching on meta.Code does not have to learn both spellings.
//
// Returns ("", false) for any code that is not a create-time limit
// refusal, so the caller can fall through and propagate the *APIError
// unchanged.
func createTimeLimitCode(code string) (ValidationCode, bool) {
	switch code {
	case "MACHINE_LIMIT_EXCEEDED":
		return ValidationCodeTooManyMachines, true
	case "CORE_LIMIT_EXCEEDED":
		return ValidationCodeTooManyCores, true
	case "MEMORY_LIMIT_EXCEEDED":
		return ValidationCodeTooMuchMemory, true
	case "DISK_LIMIT_EXCEEDED":
		return ValidationCodeTooMuchDisk, true
	default:
		return "", false
	}
}

// ActivateMachine composes CreateMachine and ValidateByID into the
// recommended "activate machine" flow: create the machine, then validate
// its license. A policy limit can stop that flow at either step, and
// ActivateMachine reports both the same way — (nil, meta, err) with err
// matching ErrMachineOverLimit (via errors.Is), NOT (machine, meta, nil).
//
// Step 1 — creation refused (422). The server enforces the machine, core,
// memory, and disk limits at creation time, so under a strict policy the
// request never produces a row. ActivateMachine short-circuits here: it
// normalizes the create-time code onto its ValidationCode equivalent
// (MACHINE_LIMIT_EXCEEDED → TOO_MANY_MACHINES, CORE_ → TOO_MANY_CORES,
// MEMORY_ → TOO_MUCH_MEMORY, DISK_ → TOO_MUCH_DISK), synthesizes a
// *ValidationMeta carrying it, and returns without calling DeleteMachine
// — there is no row to roll back, and issuing a delete against an ID that
// was never assigned would be a spurious call at best.
//
// Step 2 — creation succeeded, validation reports the overage. The
// create-time check runs through the policy's overage strategy, so a
// license under ALLOW_1_25X_OVERAGE (or ALWAYS_ALLOW_OVERAGE) is created
// past its nominal max and only reports TOO_MANY_MACHINES/TOO_MANY_CORES/
// TOO_MUCH_MEMORY/TOO_MUCH_DISK/TOO_MANY_PROCESSES from the validate
// call. Here the machine row does exist, so ActivateMachine deletes it
// before returning — implementing "reject over-limit activation" instead
// of leaving an orphaned row behind. This rollback path is unchanged and
// is still the path a permissive policy takes.
//
// In both cases the returned *Machine is nil: branching on it without
// first checking err would hand you either a machine that was never
// created or a stale, already-deleted ID, as if activation had succeeded.
// meta is populated either way so callers that want the exact
// ValidationCode (to decide messaging, retry policy, etc.) can inspect it
// despite the error. On the step-1 path meta.TS is the local time the
// refusal was observed, not a server timestamp — no validation ran.
//
// Any non-limit create error (FINGERPRINT_TAKEN, a 401, a network
// failure) propagates unchanged as (nil, nil, err).
//
// Deletion failures during rollback are not surfaced beyond that — the
// ErrMachineOverLimit/meta pair is what the caller most needs; a machine
// left behind after a failed rollback-delete is still visible to normal
// machine-management calls for manual cleanup.
func (c *Client) ActivateMachine(ctx context.Context, opts CreateMachineOptions, scope *Scope) (*Machine, *ValidationMeta, error) {
	machine, err := c.CreateMachine(ctx, opts)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if code, ok := createTimeLimitCode(apiErr.Err.Code); ok {
				meta := &ValidationMeta{
					TS:     time.Now().UTC(),
					Valid:  false,
					Code:   code,
					Detail: apiErr.Err.Detail,
				}
				// %w twice keeps both the sentinel and the original
				// *APIError in the chain, so errors.Is matches
				// ErrMachineOverLimit and ErrMachineLimitExceeded alike.
				return nil, meta, fmt.Errorf("%w (code=%s): %w", ErrMachineOverLimit, code, apiErr)
			}
		}
		return nil, nil, err
	}

	_, meta, valErr := c.ValidateByID(ctx, opts.LicenseID, &ValidateByIDOptions{Scope: scope})
	if valErr != nil {
		return machine, nil, valErr
	}

	if isOverageCode(meta.Code) {
		_ = c.DeleteMachine(ctx, machine.ID)
		return nil, meta, fmt.Errorf("%w (code=%s)", ErrMachineOverLimit, meta.Code)
	}

	return machine, meta, nil
}

// PingHeartbeat sets last_heartbeat_at = now on a machine.
// POST /v1/accounts/{account_id}/machines/{id}/actions/ping-heartbeat, no
// body. Returns the updated machine resource.
//
// It works — and revives the machine — whatever the machine's current
// HeartbeatStatus is. A DEAD machine is still pingable: the server's
// write is a bare last_heartbeat_at = NOW() with no resurrection check in
// front of it, so the status computed from that column reports the
// machine alive again on the very next read. Never skip a scheduled ping
// because the previous one came back DEAD.
//
// A 404 NOT_FOUND (errors.Is(err, ErrNotFound)) is the one response that
// does mean the row is gone — the only reliable culled/deleted signal
// this API exposes. Re-activate on that, not on DEAD. See
// HeartbeatStatus for why the two are not interchangeable.
func (c *Client) PingHeartbeat(ctx context.Context, machineID string) (*Machine, error) {
	machine, err := decodeJSONAPI[Machine](ctx, c, "POST", fmt.Sprintf("/machines/%s/actions/ping-heartbeat", escapePathSegment(machineID)), nil)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// ResetHeartbeat fully rewinds a machine's heartbeat state to
// NOT_STARTED. POST /v1/accounts/{account_id}/machines/{id}/actions/reset-heartbeat,
// no body.
//
// ⚠️ Not callable with a license key. The server gates this action on the
// caller's ROLE (admin, developer, product token, or environment token) —
// not on a permission — and the LicenseToken role is not in that set. A
// client authenticated with WithLicenseKey therefore gets 403 FORBIDDEN
// on every call, unconditionally, no matter how the license's policy is
// configured. Use a BearerAuth token with one of those roles instead.
//
// This matters more than the usual "some endpoints need a stronger
// credential" caveat, because resetting the heartbeat is the only
// server-side way to unstick a machine whose heartbeat job has wedged. An
// embedded client that reaches for it as a recovery path finds it is not
// a recovery path at all. Contrast PingHeartbeat, which is
// permission-gated with no role gate and works fine with a license key.
func (c *Client) ResetHeartbeat(ctx context.Context, machineID string) (*Machine, error) {
	machine, err := decodeJSONAPI[Machine](ctx, c, "POST", fmt.Sprintf("/machines/%s/actions/reset-heartbeat", escapePathSegment(machineID)), nil)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// HeartbeatScheduler periodically calls PingHeartbeat for one machine
// until its context is canceled. The recommended default interval is
// window/3 (~200s against the server's 600s fallback window), available
// as DefaultHeartbeatInterval. That default assumes the fallback: on a
// policy that sets a shorter heartbeat_duration it pings too slowly and
// the machine reads DEAD between ticks, so pass an explicit interval
// instead — see HeartbeatStatus's doc comment.
//
// A DEAD status observed from a ping's response is NOT a stop condition,
// and Run deliberately keeps pinging through it. DEAD only reports that
// the *previous* ping fell outside the window: the row and its seat are
// still there (under the default policy, require_heartbeat = false, they
// stay there indefinitely), and the very ping that reported DEAD has
// already revived the machine. Cancelling the scheduler on DEAD is the
// bug, not the fix.
//
// Re-activate on a 404 NOT_FOUND from the ping instead — that is the only
// signal the row is genuinely gone. Observe it with WithHeartbeatOnTick
// and errors.Is(err, ErrNotFound). See HeartbeatStatus's doc comment for
// the full server-side story.
type HeartbeatScheduler struct {
	client    *Client
	onTick    func(*Machine, error)
	machineID string
	interval  time.Duration
}

// DefaultHeartbeatInterval is machineHeartbeatWindow/3 — the recommended
// default HeartbeatScheduler interval, safely inside the server's 600s
// fallback window but NOT inside a shorter policy-configured one. Only a
// policy that leaves heartbeat_duration null is covered by this default.
const DefaultHeartbeatInterval = machineHeartbeatWindow / 3

// HeartbeatSchedulerOption configures a HeartbeatScheduler built via
// NewHeartbeatScheduler.
type HeartbeatSchedulerOption func(*HeartbeatScheduler)

// WithHeartbeatOnTick registers fn to be called after every ping attempt
// (success or error), the only way to observe each tick's outcome from
// outside this package — in particular, to catch a 404 NOT_FOUND
// (errors.Is(err, ErrNotFound)) and re-activate, or to log/alert on a
// failed ping. Without this option, Run() still pings on schedule but a
// caller has no way to observe the per-tick result short of polling the
// machine separately.
//
// A DEAD HeartbeatStatus on the returned Machine is worth logging, but it
// is not a reason to cancel the scheduler and not evidence that the
// machine was culled — the ping that reported it has already revived the
// row. Only the 404 means the row is gone. See HeartbeatScheduler's and
// HeartbeatStatus's doc comments.
func WithHeartbeatOnTick(fn func(*Machine, error)) HeartbeatSchedulerOption {
	return func(s *HeartbeatScheduler) { s.onTick = fn }
}

// NewHeartbeatScheduler builds a HeartbeatScheduler for machineID, pinging
// every DefaultHeartbeatInterval unless overridden by interval (pass 0 to
// use the default). Pass WithHeartbeatOnTick to observe each tick's
// PingHeartbeat result.
func NewHeartbeatScheduler(c *Client, machineID string, interval time.Duration, opts ...HeartbeatSchedulerOption) *HeartbeatScheduler {
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	s := &HeartbeatScheduler{client: c, machineID: machineID, interval: interval}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Run pings on Ticker's schedule until ctx is canceled, then returns
// ctx.Err(). Intended to be run in its own goroutine:
//
//	go scheduler.Run(ctx)
//
// Only ctx ends the loop. A ping that fails, or one that comes back with
// HeartbeatDead, is reported to WithHeartbeatOnTick and then the loop
// ticks again — by design, since a DEAD machine is still pingable and the
// next ping revives it. A caller that wants to react to a genuinely
// deleted row (404 NOT_FOUND) does so from the callback and cancels ctx
// itself; see HeartbeatScheduler's doc comment.
func (s *HeartbeatScheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			machine, err := s.client.PingHeartbeat(ctx, s.machineID)
			if s.onTick != nil {
				s.onTick(machine, err)
			}
		}
	}
}

// Component is the `components` JSON:API resource (Tamga API protocol
// specification §8).
type Component struct {
	ID         string              `json:"id"`
	Type       string              `json:"type"`
	Attributes ComponentAttributes `json:"attributes"`
}

// ComponentAttributes is the attribute bag of a Component resource.
type ComponentAttributes struct {
	Fingerprint string          `json:"fingerprint"`
	Name        string          `json:"name"`
	MachineID   string          `json:"machine_id"`
	Created     string          `json:"created"`
	Updated     string          `json:"updated"`
	Metadata    json.RawMessage `json:"metadata"`
}

// CreateComponentOptions configures CreateComponent. MachineID,
// Fingerprint, and Name are all required.
type CreateComponentOptions struct {
	Metadata    map[string]any
	MachineID   string
	Fingerprint string
	Name        string
}

// CreateComponent registers a component against a machine.
// POST /v1/accounts/{account_id}/components. Not JSON:API-enveloped on the
// request side (unlike CreateMachine) — the server's handler expects a
// flat {machine_id, fingerprint, name, metadata} body; this is a real
// asymmetry in the server's API, not an SDK oversight.
//
// Unique per (account_id, machine_id, fingerprint) — a duplicate fails
// with an error matching ErrFingerprintTaken (distinct call site from the
// machine one, same code).
func (c *Client) CreateComponent(ctx context.Context, opts CreateComponentOptions) (*Component, error) {
	metadata := opts.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	body := map[string]any{
		"machine_id":  opts.MachineID,
		"fingerprint": opts.Fingerprint,
		"name":        opts.Name,
		"metadata":    metadata,
	}
	component, err := decodeJSONAPI[Component](ctx, c, "POST", "/components", body)
	if err != nil {
		return nil, err
	}
	return &component, nil
}

// ComponentPage is a single page of ListComponents results.
type ComponentPage struct {
	NextCursor *string
	Items      []Component
}

// ListComponents lists a machine's components, keyset-paginated
// (limit/page[after]). GET /v1/accounts/{account_id}/machines/{id}/components.
// The response carries no cursor metadata/links of its own — NextCursor is
// set to the last item's ID when a full page was returned; pass it as the
// next call's ListOptions.After.
//
// Unlike the entitlements listing, page[after] genuinely works here.
//
// When ListOptions.Limit is unset, an explicit limit of 100 (the server
// maximum) is sent rather than letting the server apply its silent
// 25-row default. Deriving NextCursor requires knowing the page size, and
// a caller who did not pick one would otherwise get 25 rows, no cursor,
// and no indication anything was left behind.
func (c *Client) ListComponents(ctx context.Context, machineID string, opts ListOptions) (*ComponentPage, error) {
	path := fmt.Sprintf("/machines/%s/components", escapePathSegment(machineID))
	limit := effectivePageLimit(opts.Limit)
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	if opts.After != nil {
		query.Set("page[after]", *opts.After)
	}
	fullPath := path + "?" + query.Encode()
	items, err := decodeJSONAPI[[]Component](ctx, c, "GET", fullPath, nil)
	if err != nil {
		return nil, err
	}
	page := &ComponentPage{Items: items}
	if len(items) == limit {
		last := items[len(items)-1].ID
		page.NextCursor = &last
	}
	return page, nil
}

// Process is the `processes` JSON:API resource (Tamga API protocol
// specification §8).
type Process struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Attributes ProcessAttributes `json:"attributes"`
}

// ProcessAttributes is the attribute bag of a Process resource. Unlike
// Machine, there is no HeartbeatStatus field — a process's aliveness is
// entirely a function of LastHeartbeatAt versus the hardcoded 30s window;
// a dead process row is deleted immediately, not tracked in a DEAD/
// RESURRECTED state like machines.
//
// PID is a string on the wire, not an integer — the server types PID as a
// string (Tamga API protocol specification §8), and this SDK must
// send/accept PIDs as strings even though PIDs are numeric OS values;
// never silently coerce to int.
type ProcessAttributes struct {
	PID             string          `json:"pid"`
	MachineID       string          `json:"machine_id"`
	LastHeartbeatAt string          `json:"last_heartbeat_at"`
	Created         string          `json:"created"`
	Updated         string          `json:"updated"`
	Metadata        json.RawMessage `json:"metadata"`
}

// processHeartbeatWindow is the hardcoded 30-second process heartbeat
// window — much shorter than a machine's 600s default, and with no
// resurrection grace period: a dead process row is deleted immediately,
// no KEEP_DEAD equivalent (Tamga API protocol specification §8).
const processHeartbeatWindow = 30 * time.Second

// CreateProcessOptions configures CreateProcess. MachineID and PID are
// required; PID is always sent as a string, matching the server's wire
// type (Tamga API protocol specification §8) — accept a string here rather
// than a numeric type so a caller with a native numeric PID must
// explicitly stringify it (strconv.Itoa(pid)), making the string-not-int
// wire contract visible at the call site instead of silently coercing.
type CreateProcessOptions struct {
	Metadata  map[string]any
	MachineID string
	PID       string
}

// CreateProcess registers a process against a machine.
// POST /v1/accounts/{account_id}/processes. Same flat (non-JSON:API)
// request body shape as CreateComponent — see that method's doc comment.
//
// Unique PID per machine — a duplicate fails with an error matching
// ErrPIDTaken. Unlike a machine (which starts NOT_STARTED), a process
// starts ALIVE immediately — its LastHeartbeatAt is set at creation, not
// left unset until a first ping.
func (c *Client) CreateProcess(ctx context.Context, opts CreateProcessOptions) (*Process, error) {
	metadata := opts.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	body := map[string]any{
		"machine_id": opts.MachineID,
		"pid":        opts.PID,
		"metadata":   metadata,
	}
	process, err := decodeJSONAPI[Process](ctx, c, "POST", "/processes", body)
	if err != nil {
		return nil, err
	}
	return &process, nil
}

// PingProcess sends a process heartbeat ping.
// POST /v1/accounts/{account_id}/processes/{id}/actions/ping, no body.
//
// The process heartbeat window is a hardcoded 30 seconds with no
// resurrection grace period — see ProcessHeartbeatScheduler's doc comment.
func (c *Client) PingProcess(ctx context.Context, processID string) (*Process, error) {
	process, err := decodeJSONAPI[Process](ctx, c, "POST", fmt.Sprintf("/processes/%s/actions/ping", escapePathSegment(processID)), nil)
	if err != nil {
		return nil, err
	}
	return &process, nil
}

// DefaultProcessHeartbeatInterval is the recommended ProcessHeartbeatScheduler
// interval — at least every ~10s to stay safely inside the hardcoded 30s
// process heartbeat window (Tamga API protocol specification §8).
const DefaultProcessHeartbeatInterval = processHeartbeatWindow / 3

// ProcessHeartbeatScheduler periodically calls PingProcess for one process
// until its context is canceled. Ping at least every ~10s
// (DefaultProcessHeartbeatInterval) to stay safely inside the hardcoded
// 30s process heartbeat window — unlike machines, a dead process row is
// deleted immediately with no resurrection grace period.
type ProcessHeartbeatScheduler struct {
	client    *Client
	onTick    func(*Process, error)
	processID string
	interval  time.Duration
}

// ProcessHeartbeatSchedulerOption configures a ProcessHeartbeatScheduler
// built via NewProcessHeartbeatScheduler.
type ProcessHeartbeatSchedulerOption func(*ProcessHeartbeatScheduler)

// WithProcessHeartbeatOnTick registers fn to be called after every ping
// attempt (success or error) — the only way to observe each tick's
// outcome from outside this package. See WithHeartbeatOnTick's doc
// comment for the equivalent on HeartbeatScheduler; this is the same
// pattern for processes, whose hardcoded 30s window and lack of a
// resurrection grace period make observing a failed ping promptly more
// important than for machines.
func WithProcessHeartbeatOnTick(fn func(*Process, error)) ProcessHeartbeatSchedulerOption {
	return func(s *ProcessHeartbeatScheduler) { s.onTick = fn }
}

// NewProcessHeartbeatScheduler builds a ProcessHeartbeatScheduler for
// processID, pinging every DefaultProcessHeartbeatInterval unless
// overridden by interval (pass 0 to use the default). Pass
// WithProcessHeartbeatOnTick to observe each tick's PingProcess result.
func NewProcessHeartbeatScheduler(c *Client, processID string, interval time.Duration, opts ...ProcessHeartbeatSchedulerOption) *ProcessHeartbeatScheduler {
	if interval <= 0 {
		interval = DefaultProcessHeartbeatInterval
	}
	s := &ProcessHeartbeatScheduler{client: c, processID: processID, interval: interval}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Run pings on Ticker's schedule until ctx is canceled, then returns
// ctx.Err(). Intended to be run in its own goroutine, same pattern as
// HeartbeatScheduler.Run.
func (s *ProcessHeartbeatScheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			process, err := s.client.PingProcess(ctx, s.processID)
			if s.onTick != nil {
				s.onTick(process, err)
			}
		}
	}
}
