package tamga

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// ProcessPage is a single page of ListMachineProcesses results.
//
// Keyset-paginated with a synthetic cursor, exactly like ComponentPage —
// and unlike MachinePage, which is offset-paginated because the parent
// collection GET /machines is. The machine collection and its own
// sub-collections genuinely disagree about pagination style; this is the
// sub-collection side of that split.
type ProcessPage struct {
	NextCursor *string
	Items      []Process
}

// ListMachineProcesses lists a machine's processes, keyset-paginated
// (limit/page[after]).
// GET /v1/accounts/{account_id}/machines/{id}/processes.
//
// The response carries no cursor metadata and no links, so NextCursor is
// derived: it is set to the last item's ID when a full page came back and
// left nil on a short or empty page. Feed it to the next call as
// ListOptions.After. Sizing matters for that rule to hold, so an unset
// ListOptions.Limit sends an explicit limit of 100 (the server maximum)
// rather than accepting the server's silent 25-row default.
//
// GET-only: the server exposes no POST on this path. Create a process
// with CreateProcess, which posts a flat body to /processes.
//
// A process listed here counts against the policy's max_processes and
// will keep counting until something deletes it — see DeleteProcess.
func (c *Client) ListMachineProcesses(ctx context.Context, machineID string, opts ListOptions) (*ProcessPage, error) {
	path := fmt.Sprintf("/machines/%s/processes", escapePathSegment(machineID))
	limit := effectivePageLimit(opts.Limit)
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	if opts.After != nil {
		query.Set("page[after]", *opts.After)
	}
	items, err := decodeJSONAPI[[]Process](ctx, c, "GET", path+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	page := &ProcessPage{Items: items}
	if len(items) == limit {
		last := items[len(items)-1].ID
		page.NextCursor = &last
	}
	return page, nil
}

// DeleteProcess deletes a process row.
// DELETE /v1/accounts/{account_id}/processes/{id}. Returns 204 with no
// body; only the mapped error, if any, is surfaced.
//
// ⚠️ This is not an optimization, it is the only cleanup that happens.
// The server has no working process reaper — the background job that
// would delete rows whose last_heartbeat_at fell outside the hardcoded
// 30s window is dead code — so a process row created by CreateProcess
// lives until a client explicitly deletes it. Nothing expires it, and
// ProcessAttributes has no heartbeat status to reveal that it went stale.
//
// The cost is not cosmetic: every surviving row counts against the
// policy's max_processes, so a long-lived install that registers a
// process per run and never deletes one eventually reports
// TOO_MANY_PROCESSES on an activation that is otherwise perfectly
// legitimate. Pair every CreateProcess with a DeleteProcess on shutdown —
// ProcessHeartbeatScheduler.Dispose is that call, wired to the process a
// scheduler was already pinging.
//
// Deleting a process that is already gone is a 404 NOT_FOUND
// (errors.Is(err, ErrNotFound)), which for a shutdown path is usually
// success rather than a failure worth reporting.
func (c *Client) DeleteProcess(ctx context.Context, processID string) error {
	return doNoContent(ctx, c, "DELETE", fmt.Sprintf("/processes/%s", escapePathSegment(processID)))
}

// Dispose deletes the process this scheduler has been pinging.
//
// It takes its own context rather than reusing Run's, deliberately:
// Run only ever returns because its context was canceled, and issuing a
// DELETE on a canceled context fails before it reaches the network. Call
// it with a fresh, short-deadline context from the shutdown path:
//
//	go scheduler.Run(ctx)
//	<-shutdown
//	cancel()
//	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
//	defer done()
//	_ = scheduler.Dispose(ctx)
//
// Stopping the pings is not enough on its own. Nothing server-side reaps
// a process row whose heartbeat has lapsed, so a scheduler that is merely
// canceled leaves the row — and its claim on the policy's max_processes —
// behind permanently. See DeleteProcess.
func (s *ProcessHeartbeatScheduler) Dispose(ctx context.Context) error {
	return s.client.DeleteProcess(ctx, s.processID)
}
