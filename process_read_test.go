package tamga

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func processJSON(id, pid string) string {
	return fmt.Sprintf(`{
		"id":%q,"type":"processes",
		"attributes":{
			"pid":%q,"machine_id":"mach-1","last_heartbeat_at":"2026-01-01T00:00:00Z",
			"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"
		}
	}`, id, pid)
}

func TestListMachineProcesses_KeysetQueryAndDerivedCursor(t *testing.T) {
	var gotPath string
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + processJSON("p1", "111") + `,` + processJSON("p2", "222") + `]}`))
	})
	defer closeFn()

	page, err := c.ListMachineProcesses(context.Background(), "mach-1", ListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListMachineProcesses() error = %v", err)
	}
	if gotPath != "/v1/accounts/acct-123/machines/mach-1/processes" {
		t.Errorf("path = %s", gotPath)
	}
	// Keyset, not offset: this sub-collection uses a bare limit, not
	// page[size]/page[number] like its own parent GET /machines.
	if got := gotQuery.Get("limit"); got != "2" {
		t.Errorf("limit = %q", got)
	}
	for _, offsetParam := range []string{"page[size]", "page[number]"} {
		if _, ok := gotQuery[offsetParam]; ok {
			t.Errorf("%s was sent to a keyset route", offsetParam)
		}
	}
	if page.NextCursor == nil || *page.NextCursor != "p2" {
		t.Errorf("NextCursor = %v, want the last item's id on a full page", page.NextCursor)
	}
	// pid stays a string on the wire in both directions.
	if page.Items[0].Attributes.PID != "111" {
		t.Errorf("PID = %q", page.Items[0].Attributes.PID)
	}
}

func TestListMachineProcesses_ShortPageLeavesTheCursorNil(t *testing.T) {
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + processJSON("p1", "111") + `]}`))
	})
	defer closeFn()

	page, err := c.ListMachineProcesses(context.Background(), "mach-1", ListOptions{})
	if err != nil {
		t.Fatalf("ListMachineProcesses() error = %v", err)
	}
	if got := gotQuery.Get("limit"); got != "100" {
		t.Errorf("limit = %q, want the server maximum when unset", got)
	}
	if page.NextCursor != nil {
		t.Errorf("NextCursor = %v, want nil on a short page", *page.NextCursor)
	}
}

func TestListMachineProcesses_ForwardsTheCursorAsPageAfter(t *testing.T) {
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	defer closeFn()

	after := "p2"
	if _, err := c.ListMachineProcesses(context.Background(), "mach-1", ListOptions{After: &after}); err != nil {
		t.Fatalf("ListMachineProcesses() error = %v", err)
	}
	if got := gotQuery.Get("page[after]"); got != "p2" {
		t.Errorf("page[after] = %q", got)
	}
}

func TestDeleteProcess_SendsDeleteAndAcceptsNoContent(t *testing.T) {
	var gotMethod, gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.EscapedPath()
		w.WriteHeader(http.StatusNoContent)
	})
	defer closeFn()

	if err := c.DeleteProcess(context.Background(), "proc/1"); err != nil {
		t.Fatalf("DeleteProcess() error = %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %s", gotMethod)
	}
	if gotPath != "/v1/accounts/acct-123/processes/proc%2F1" {
		t.Errorf("escaped path = %s", gotPath)
	}
}

func TestDeleteProcess_MapsAMissingRowToNotFound(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"status":"404","code":"NOT_FOUND","title":"Not Found","detail":"gone"}]}`))
	})
	defer closeFn()

	err := c.DeleteProcess(context.Background(), "proc-1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("errors.Is(err, ErrNotFound) = false, err = %v", err)
	}
}

func TestProcessHeartbeatSchedulerDispose_DeletesTheProcessItWasPinging(t *testing.T) {
	var gotMethod, gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	defer closeFn()

	scheduler := NewProcessHeartbeatScheduler(c, "proc-9", 0)
	if err := scheduler.Dispose(context.Background()); err != nil {
		t.Fatalf("Dispose() error = %v", err)
	}
	if gotMethod != http.MethodDelete || !strings.HasSuffix(gotPath, "/processes/proc-9") {
		t.Errorf("Dispose() sent %s %s", gotMethod, gotPath)
	}
}
