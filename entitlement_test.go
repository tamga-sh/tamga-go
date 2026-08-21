package tamga

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const representativeEntitlementJSONTmpl = `{"id":"%s","type":"entitlements","attributes":{"name":"%s","code":"%s","metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}`

// The entitlements listing is a union of direct and policy-inherited
// rows, which no single keyset cursor over one table can describe, so the
// server accepts page[after] for wire compatibility and then ignores it —
// the same first page comes back forever. Emitting a cursor here would
// hand callers a loop that never terminates.
func TestListEntitlements_NeverPaginates(t *testing.T) {
	var gotQuery string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` +
			sprintfEnt("ent-1", "Pro Features", "pro") + "," +
			sprintfEnt("ent-2", "Beta Access", "beta") + `]}`))
	})
	defer closeFn()

	after := "ent-0"
	page, err := c.ListEntitlements(context.Background(), "lic-id", ListOptions{Limit: 2, After: &after})
	if err != nil {
		t.Fatalf("ListEntitlements() error = %v", err)
	}
	if !strings.Contains(gotQuery, "limit=2") {
		t.Errorf("query = %q, want the caller's explicit limit", gotQuery)
	}
	if strings.Contains(gotQuery, "page%5Bafter%5D") {
		t.Errorf("query = %q, want no page[after] — the server ignores it on this route", gotQuery)
	}
	if len(page.Items) != 2 {
		t.Errorf("len(Items) = %d, want 2", len(page.Items))
	}
	// A full page must still not produce a cursor: "the page was full" is
	// not evidence there is a next page on a route that cannot paginate.
	if page.NextCursor != nil {
		t.Errorf("NextCursor = %q, want nil on every entitlements page", *page.NextCursor)
	}
}

// Without an explicit limit the server silently applies its own 25-row
// default and emits no page metadata, so a caller cannot tell a complete
// answer from a truncated one. Send the server maximum instead.
func TestListEntitlements_SendsMaxLimitWhenUnset(t *testing.T) {
	var gotQuery string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + sprintfEnt("ent-1", "Pro Features", "pro") + `]}`))
	})
	defer closeFn()

	if _, err := c.ListEntitlements(context.Background(), "lic-id", ListOptions{}); err != nil {
		t.Fatalf("ListEntitlements() error = %v", err)
	}
	if !strings.Contains(gotQuery, "limit=100") {
		t.Errorf("query = %q, want limit=100 (the server max), not the silent 25-row default", gotQuery)
	}
}

// The inherited flag decides whether an entitlement can be detached, can
// be attached directly, and whether GetEntitlement resolves it at all —
// dropping it during decode loses all three.
func TestListEntitlements_DecodesInheritedFlag(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` +
			`{"id":"ent-1","type":"entitlements","attributes":{"name":"Pro","code":"pro","inherited":true,` +
			`"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}},` +
			`{"id":"ent-2","type":"entitlements","attributes":{"name":"Beta","code":"beta","inherited":false,` +
			`"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}]}`))
	})
	defer closeFn()

	page, err := c.ListEntitlements(context.Background(), "lic-id", ListOptions{})
	if err != nil {
		t.Fatalf("ListEntitlements() error = %v", err)
	}
	if page.Items[0].Attributes.Inherited == nil || !*page.Items[0].Attributes.Inherited {
		t.Errorf("ent-1 Inherited = %v, want true", page.Items[0].Attributes.Inherited)
	}
	if page.Items[1].Attributes.Inherited == nil || *page.Items[1].Attributes.Inherited {
		t.Errorf("ent-2 Inherited = %v, want false", page.Items[1].Attributes.Inherited)
	}
}

// Account-, policy-, and release-scoped responses omit the attribute
// entirely; nil must mean "the server did not say", never false.
func TestListEntitlements_AbsentInheritedIsNilNotFalse(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + sprintfEnt("ent-1", "Pro Features", "pro") + `]}`))
	})
	defer closeFn()

	page, err := c.ListEntitlements(context.Background(), "lic-id", ListOptions{})
	if err != nil {
		t.Fatalf("ListEntitlements() error = %v", err)
	}
	if page.Items[0].Attributes.Inherited != nil {
		t.Errorf("Inherited = %v, want nil when the server omits the field", *page.Items[0].Attributes.Inherited)
	}
}

func TestGetEntitlement_SingleFetch(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/licenses/lic-id/entitlements/ent-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + sprintfEnt("ent-1", "Pro Features", "pro") + `}`))
	})
	defer closeFn()

	entitlement, err := c.GetEntitlement(context.Background(), "lic-id", "ent-1")
	if err != nil {
		t.Fatalf("GetEntitlement() error = %v", err)
	}
	if entitlement.Attributes.Code != "pro" {
		t.Errorf("Code = %q", entitlement.Attributes.Code)
	}
}

func TestHasEntitlement_MatchesOnCodeNotName(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		// Name of the second entitlement equals the code we're searching
		// for below ("pro"), to prove HasEntitlement never matches on Name.
		_, _ = w.Write([]byte(`{"data":[` +
			sprintfEnt("ent-1", "pro", "beta") + "," +
			sprintfEnt("ent-2", "Pro Features", "pro") + `]}`))
	})
	defer closeFn()

	has, err := c.HasEntitlement(context.Background(), "lic-id", "pro")
	if err != nil {
		t.Fatalf("HasEntitlement() error = %v", err)
	}
	if !has {
		t.Fatal("HasEntitlement(\"pro\") = false, want true (matches ent-2's Code)")
	}

	hasBeta, err := c.HasEntitlement(context.Background(), "lic-id", "beta")
	if err != nil {
		t.Fatalf("HasEntitlement() error = %v", err)
	}
	if !hasBeta {
		t.Fatal("HasEntitlement(\"beta\") = false, want true (matches ent-1's Code)")
	}
}

func TestHasEntitlement_CacheHitAvoidsSecondHTTPCall(t *testing.T) {
	var calls int
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + sprintfEnt("ent-1", "Pro Features", "pro") + `]}`))
	})
	defer closeFn()

	if _, err := c.HasEntitlement(context.Background(), "lic-id", "pro"); err != nil {
		t.Fatalf("HasEntitlement() error = %v", err)
	}
	if _, err := c.HasEntitlement(context.Background(), "lic-id", "pro"); err != nil {
		t.Fatalf("HasEntitlement() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (second call should hit the TTL cache)", calls)
	}

	c.InvalidateEntitlementCache("lic-id")
	if _, err := c.HasEntitlement(context.Background(), "lic-id", "pro"); err != nil {
		t.Fatalf("HasEntitlement() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 after explicit cache invalidation", calls)
	}
}

// TestHasEntitlement_ConcurrentAccessIsRaceFree exercises the
// entitlementCache's sync.Mutex-protected lazy-init (entCacheOnce) and
// read/write paths from many goroutines at once, across several license
// IDs (so both the "first fetch populates the cache" and "concurrent
// readers hit an already-populated entry" code paths run concurrently).
// Run with `go test -race` to actually catch a data race, not just
// exercise the code.
func TestHasEntitlement_ConcurrentAccessIsRaceFree(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + sprintfEnt("ent-1", "Pro Features", "pro") + `]}`))
	})
	defer closeFn()

	const goroutines = 50
	const licenseIDs = 5
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			licenseID := fmt.Sprintf("lic-%d", i%licenseIDs)
			has, err := c.HasEntitlement(context.Background(), licenseID, "pro")
			if err != nil {
				errs <- err
				return
			}
			if !has {
				errs <- fmt.Errorf("HasEntitlement(%q, \"pro\") = false, want true", licenseID)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func sprintfEnt(id, name, code string) string {
	return fmt.Sprintf(representativeEntitlementJSONTmpl, id, name, code)
}

// ExampleClient_HasEntitlement demonstrates checking whether a license has
// a given entitlement, matching on Code (never Name — see
// EntitlementAttributes' doc comment). See examples/entitlements/main.go
// for a full runnable program.
func ExampleClient_HasEntitlement() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + sprintfEnt("ent-1", "Pro Features", "pro") + `]}`))
	}))
	defer server.Close()

	client, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc123"))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	has, err := client.HasEntitlement(context.Background(), "lic-id", "pro")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("has \"pro\" entitlement:", has)
	// Output: has "pro" entitlement: true
}
