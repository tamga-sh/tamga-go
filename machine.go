package tamga

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Machine is the `machines` JSON:API resource (docs/sdk.md §5). Field set
// matches the server's actual MachineResource/MachineAttributes
// serializer — no relationships object, same as License.
type Machine struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Attributes MachineAttributes `json:"attributes"`
}

// MachineAttributes is the attribute bag of a Machine resource.
type MachineAttributes struct {
	Platform        *string         `json:"platform"`
	NextHeartbeatAt *string         `json:"next_heartbeat_at"`
	Memory          *int64          `json:"memory"`
	Disk            *int64          `json:"disk"`
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
// The window is a hardcoded 600s (10 min), not driven by
// policy.heartbeat_duration despite that field existing on Policy
// (docs/sdk.md's Known Server-Side Gaps #8). Treat DEAD as "machine likely
// deleted server-side — re-activate rather than retry ping," per the
// policy's HeartbeatCullStrategy.
type HeartbeatStatus string

// Heartbeat status constants — see HeartbeatStatus's doc comment for the
// state machine and the hardcoded-window gotcha.
const (
	HeartbeatNotStarted  HeartbeatStatus = "NOT_STARTED"
	HeartbeatAlive       HeartbeatStatus = "ALIVE"
	HeartbeatDead        HeartbeatStatus = "DEAD"
	HeartbeatResurrected HeartbeatStatus = "RESURRECTED"
)

// machineHeartbeatWindow is the hardcoded 600-second (10 min) machine
// heartbeat window — see HeartbeatStatus's doc comment.
const machineHeartbeatWindow = 600 * time.Second

// CreateMachineOptions configures CreateMachine. Fingerprint and LicenseID
// are required; every other field is optional.
type CreateMachineOptions struct {
	Name        *string
	IP          *string
	Hostname    *string
	Platform    *string
	Cores       *int32
	Memory      *int64
	Disk        *int64
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
// No machine/core/etc. limit is checked at creation time — those limits
// only surface later via license validation (ValidateByID). The machine
// row may already exist even if the license is over its limit; the caller
// is responsible for deleting it if the desired UX is "reject over-limit
// activation" — see ActivateMachine, which does exactly that.
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

// ActivateMachine composes CreateMachine and ValidateByID into the
// recommended "activate machine" flow: create the machine, then validate
// its license. If validation returns an over-limit ValidationCode
// (TOO_MANY_MACHINES/TOO_MANY_CORES/TOO_MUCH_MEMORY/TOO_MUCH_DISK/
// TOO_MANY_PROCESSES), the just-created machine is deleted before
// returning — implementing "reject over-limit activation" instead of
// leaving an orphaned machine row behind (see CreateMachine's doc comment
// for why creation alone doesn't enforce limits).
//
// On that rollback path, ActivateMachine returns (nil, meta, err) with err
// matching ErrMachineOverLimit (via errors.Is) — NOT (machine, meta, nil).
// The machine has already been deleted server-side by the time this
// returns, so branching on the returned machine without first checking err
// would hand you a stale, deleted machine's ID as if activation had
// succeeded. meta is still populated so callers that want the exact
// ValidationCode (to decide messaging, retry policy, etc.) can inspect it
// despite the error.
//
// Deletion failures during rollback are not surfaced beyond that — the
// ErrMachineOverLimit/meta pair is what the caller most needs; a machine
// left behind after a failed rollback-delete is still visible to normal
// machine-management calls for manual cleanup.
func (c *Client) ActivateMachine(ctx context.Context, opts CreateMachineOptions, scope *Scope) (*Machine, *ValidationMeta, error) {
	machine, err := c.CreateMachine(ctx, opts)
	if err != nil {
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
func (c *Client) ResetHeartbeat(ctx context.Context, machineID string) (*Machine, error) {
	machine, err := decodeJSONAPI[Machine](ctx, c, "POST", fmt.Sprintf("/machines/%s/actions/reset-heartbeat", escapePathSegment(machineID)), nil)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// HeartbeatScheduler periodically calls PingHeartbeat for one machine
// until its context is canceled. The recommended default interval is
// window/3 (~200s for the hardcoded 600s machine window), available as
// DefaultHeartbeatInterval. Treat a DEAD status observed from a ping's
// response as "machine likely deleted server-side — re-activate rather
// than retry ping," per HeartbeatStatus's doc comment.
type HeartbeatScheduler struct {
	client    *Client
	onTick    func(*Machine, error)
	machineID string
	interval  time.Duration
}

// DefaultHeartbeatInterval is machineHeartbeatWindow/3 — the recommended
// default HeartbeatScheduler interval, safely inside the hardcoded 600s
// machine heartbeat window.
const DefaultHeartbeatInterval = machineHeartbeatWindow / 3

// HeartbeatSchedulerOption configures a HeartbeatScheduler built via
// NewHeartbeatScheduler.
type HeartbeatSchedulerOption func(*HeartbeatScheduler)

// WithHeartbeatOnTick registers fn to be called after every ping attempt
// (success or error), the only way to observe each tick's outcome from
// outside this package — in particular, to detect a DEAD HeartbeatStatus
// on the returned Machine and react per HeartbeatScheduler's doc comment
// ("re-activate rather than retry ping"), or to log/alert on a failed
// ping. Without this option, Run() still pings on schedule but a caller
// has no way to observe the per-tick result short of polling the machine
// separately.
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

// Component is the `components` JSON:API resource (docs/sdk.md §8).
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
func (c *Client) ListComponents(ctx context.Context, machineID string, opts ListOptions) (*ComponentPage, error) {
	path := fmt.Sprintf("/machines/%s/components", escapePathSegment(machineID))
	query := url.Values{}
	if opts.Limit > 0 {
		query.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.After != nil {
		query.Set("page[after]", *opts.After)
	}
	fullPath := path
	if encoded := query.Encode(); encoded != "" {
		fullPath += "?" + encoded
	}
	items, err := decodeJSONAPI[[]Component](ctx, c, "GET", fullPath, nil)
	if err != nil {
		return nil, err
	}
	page := &ComponentPage{Items: items}
	if opts.Limit > 0 && len(items) == opts.Limit {
		last := items[len(items)-1].ID
		page.NextCursor = &last
	}
	return page, nil
}

// Process is the `processes` JSON:API resource (docs/sdk.md §8).
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
// string (docs/sdk.md §8), and this SDK must send/accept PIDs as strings
// even though PIDs are numeric OS values; never silently coerce to int.
type ProcessAttributes struct {
	PID             string          `json:"pid"`
	MachineID       string          `json:"machine_id"`
	LastHeartbeatAt string          `json:"last_heartbeat_at"`
	Created         string          `json:"created"`
	Updated         string          `json:"updated"`
	Metadata        json.RawMessage `json:"metadata"`
}

// processHeartbeatWindow is the hardcoded 30-second process heartbeat
// window — much shorter than a machine's 600s, and with no resurrection
// grace period: a dead process row is deleted immediately, no KEEP_DEAD
// equivalent (docs/sdk.md §8).
const processHeartbeatWindow = 30 * time.Second

// CreateProcessOptions configures CreateProcess. MachineID and PID are
// required; PID is always sent as a string, matching the server's wire
// type (docs/sdk.md §8) — accept a string here rather than a numeric type
// so a caller with a native numeric PID must explicitly stringify it
// (strconv.Itoa(pid)), making the string-not-int wire contract visible at
// the call site instead of silently coercing.
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
// process heartbeat window (docs/sdk.md §8).
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
