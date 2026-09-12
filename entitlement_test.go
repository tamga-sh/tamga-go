package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Kind is always present, on every response shape — never a pointer or an
// omitted addition, unlike Inherited/MaxValue/CurrentValue.
func TestListEntitlements_DecodesKind(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` +
			`{"id":"ent-1","type":"entitlements","attributes":{"name":"Pro","code":"pro","kind":"flag",` +
			`"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}},` +
			`{"id":"ent-2","type":"entitlements","attributes":{"name":"Requests","code":"requests","kind":"meter",` +
			`"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}]}`))
	})
	defer closeFn()

	page, err := c.ListEntitlements(context.Background(), "lic-id", ListOptions{})
	if err != nil {
		t.Fatalf("ListEntitlements() error = %v", err)
	}
	if page.Items[0].Attributes.Kind != EntitlementKindFlag {
		t.Errorf("ent-1 Kind = %q, want %q", page.Items[0].Attributes.Kind, EntitlementKindFlag)
	}
	if page.Items[1].Attributes.Kind != EntitlementKindMeter {
		t.Errorf("ent-2 Kind = %q, want %q", page.Items[1].Attributes.Kind, EntitlementKindMeter)
	}
}

// An unrecognized kind value must decode cleanly, matching ValidationCode's
// forward-compatibility rule (EntitlementKind is a plain string type, not a
// closed Go enum).
func TestEntitlementKind_UnknownValuePassthrough(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` +
			`{"id":"ent-1","type":"entitlements","attributes":{"name":"Future","code":"future","kind":"SOME_FUTURE_KIND",` +
			`"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
	})
	defer closeFn()

	entitlement, err := c.GetEntitlement(context.Background(), "lic-id", "ent-1")
	if err != nil {
		t.Fatalf("GetEntitlement() error = %v", err)
	}
	if entitlement.Attributes.Kind != EntitlementKind("SOME_FUTURE_KIND") {
		t.Errorf("Kind = %q, want SOME_FUTURE_KIND", entitlement.Attributes.Kind)
	}
}

// MaxValue/CurrentValue follow Inherited's own "present only on the
// license-scoped route" pointer convention: nil means the server didn't
// say, not zero/unlimited.
func TestListEntitlements_DecodesMeterValues(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` +
			`{"id":"ent-1","type":"entitlements","attributes":{"name":"Requests","code":"requests","kind":"meter",` +
			`"inherited":false,"max_value":1000,"current_value":650,` +
			`"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}},` +
			`{"id":"ent-2","type":"entitlements","attributes":{"name":"Exports","code":"exports","kind":"meter",` +
			`"inherited":false,"max_value":null,"current_value":0,` +
			`"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}]}`))
	})
	defer closeFn()

	page, err := c.ListEntitlements(context.Background(), "lic-id", ListOptions{})
	if err != nil {
		t.Fatalf("ListEntitlements() error = %v", err)
	}
	ent1 := page.Items[0].Attributes
	if ent1.MaxValue == nil || *ent1.MaxValue != 1000 {
		t.Errorf("ent-1 MaxValue = %v, want 1000", ent1.MaxValue)
	}
	if ent1.CurrentValue == nil || *ent1.CurrentValue != 650 {
		t.Errorf("ent-1 CurrentValue = %v, want 650", ent1.CurrentValue)
	}
	ent2 := page.Items[1].Attributes
	if ent2.MaxValue != nil {
		t.Errorf("ent-2 MaxValue = %v, want nil (unlimited)", *ent2.MaxValue)
	}
	if ent2.CurrentValue == nil || *ent2.CurrentValue != 0 {
		t.Errorf("ent-2 CurrentValue = %v, want 0 (present, never incremented)", ent2.CurrentValue)
	}
}

func TestGetEntitlement_AbsentMeterValuesAreNilNotZero(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + sprintfEnt("ent-1", "Pro Features", "pro") + `}`))
	})
	defer closeFn()

	entitlement, err := c.GetEntitlement(context.Background(), "lic-id", "ent-1")
	if err != nil {
		t.Fatalf("GetEntitlement() error = %v", err)
	}
	if entitlement.Attributes.MaxValue != nil {
		t.Errorf("MaxValue = %v, want nil when the server omits the field", *entitlement.Attributes.MaxValue)
	}
	if entitlement.Attributes.CurrentValue != nil {
		t.Errorf("CurrentValue = %v, want nil when the server omits the field", *entitlement.Attributes.CurrentValue)
	}
}

func TestIncrementEntitlementUsage_DefaultsAndExplicitIncrement(t *testing.T) {
	var gotBody map[string]any
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"ent-1","type":"entitlements","attributes":{"name":"Requests","code":"requests","kind":"meter","inherited":false,"max_value":1000,"current_value":4,"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
	})
	defer closeFn()

	entitlement, err := c.IncrementEntitlementUsage(context.Background(), "lic-id", "ent-1", nil)
	if err != nil {
		t.Fatalf("IncrementEntitlementUsage() error = %v", err)
	}
	if !strings.HasSuffix(gotPath, "/licenses/lic-id/entitlements/ent-1/actions/increment") {
		t.Errorf("path = %s", gotPath)
	}
	if gotBody != nil {
		t.Errorf("body = %v, want no body when increment is nil", gotBody)
	}
	if entitlement.Attributes.CurrentValue == nil || *entitlement.Attributes.CurrentValue != 4 {
		t.Errorf("CurrentValue = %v, want 4", entitlement.Attributes.CurrentValue)
	}

	three := int32(3)
	if _, err := c.IncrementEntitlementUsage(context.Background(), "lic-id", "ent-1", &three); err != nil {
		t.Fatalf("IncrementEntitlementUsage() error = %v", err)
	}
	if got, ok := gotBody["increment"].(float64); !ok || int32(got) != 3 {
		t.Errorf("body[increment] = %v, want 3", gotBody["increment"])
	}
}

func TestDecrementEntitlementUsage_SendsDecrementBody(t *testing.T) {
	var gotBody map[string]any
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"ent-1","type":"entitlements","attributes":{"name":"Requests","code":"requests","kind":"meter","inherited":false,"max_value":1000,"current_value":0,"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
	})
	defer closeFn()

	two := int32(2)
	entitlement, err := c.DecrementEntitlementUsage(context.Background(), "lic-id", "ent-1", &two)
	if err != nil {
		t.Fatalf("DecrementEntitlementUsage() error = %v", err)
	}
	if !strings.HasSuffix(gotPath, "/licenses/lic-id/entitlements/ent-1/actions/decrement") {
		t.Errorf("path = %s", gotPath)
	}
	if got, ok := gotBody["decrement"].(float64); !ok || int32(got) != 2 {
		t.Errorf("body[decrement] = %v, want 2", gotBody["decrement"])
	}
	if entitlement.Attributes.CurrentValue == nil || *entitlement.Attributes.CurrentValue != 0 {
		t.Errorf("CurrentValue = %v, want 0 (floored)", entitlement.Attributes.CurrentValue)
	}
}

func TestResetEntitlementUsage_NoBodySentAndCurrentValueZeroed(t *testing.T) {
	var gotBody []byte
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"ent-1","type":"entitlements","attributes":{"name":"Requests","code":"requests","kind":"meter","inherited":false,"max_value":1000,"current_value":0,"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
	})
	defer closeFn()

	entitlement, err := c.ResetEntitlementUsage(context.Background(), "lic-id", "ent-1")
	if err != nil {
		t.Fatalf("ResetEntitlementUsage() error = %v", err)
	}
	if !strings.HasSuffix(gotPath, "/licenses/lic-id/entitlements/ent-1/actions/reset") {
		t.Errorf("path = %s", gotPath)
	}
	if len(gotBody) != 0 {
		t.Errorf("body = %q, want empty", gotBody)
	}
	if entitlement.Attributes.CurrentValue == nil || *entitlement.Attributes.CurrentValue != 0 {
		t.Errorf("CurrentValue = %v, want 0", entitlement.Attributes.CurrentValue)
	}
}

func TestIncrementEntitlementUsage_MeterLimitExceeded(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":[{"status":"422","code":"METER_LIMIT_EXCEEDED","title":"Unprocessable Entity","detail":"meter cap exceeded","meta":{"entitlement_id":"ent-1"}}]}`))
	})
	defer closeFn()

	_, err := c.IncrementEntitlementUsage(context.Background(), "lic-id", "ent-1", nil)
	if !errors.Is(err, ErrMeterLimitExceeded) {
		t.Fatalf("errors.Is(err, ErrMeterLimitExceeded) = false, err = %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As() = false")
	}
	id, ok := apiErr.MeterEntitlementID()
	if !ok || id != "ent-1" {
		t.Errorf("MeterEntitlementID() = (%q, %v), want (\"ent-1\", true)", id, ok)
	}
}

func TestIncrementEntitlementUsage_NotFoundWhenOnlyInherited(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"status":"404","code":"NOT_FOUND","title":"Not Found","detail":"no direct attachment"}]}`))
	})
	defer closeFn()

	_, err := c.IncrementEntitlementUsage(context.Background(), "lic-id", "ent-1", nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("errors.Is(err, ErrNotFound) = false, err = %v", err)
	}
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
