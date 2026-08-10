package tamga

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const representativeEntitlementJSONTmpl = `{"id":"%s","type":"entitlements","attributes":{"name":"%s","code":"%s","metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}`

func TestListEntitlements_Pagination(t *testing.T) {
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
	if !strings.Contains(gotQuery, "limit=2") || !strings.Contains(gotQuery, "page%5Bafter%5D=ent-0") {
		t.Errorf("query = %q", gotQuery)
	}
	if len(page.Items) != 2 || page.NextCursor == nil || *page.NextCursor != "ent-2" {
		t.Errorf("page = %+v", page)
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
