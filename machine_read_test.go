package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// machineJSONWithFingerprint renders one machines resource with the given
// id and fingerprint, reading DEAD — the status only the read routes can
// produce.
func machineJSONWithFingerprint(id, fingerprint string) string {
	return fmt.Sprintf(`{
		"id":%q,"type":"machines",
		"attributes":{
			"fingerprint":%q,"cores":null,"memory":null,"disk":null,"ip":null,
			"hostname":null,"platform":"linux","name":null,"heartbeat_status":"DEAD",
			"last_heartbeat_at":"2026-01-01T00:00:00Z","next_heartbeat_at":"2026-01-01T00:01:00Z",
			"last_check_out_at":null,"metadata":{},
			"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"
		}
	}`, id, fingerprint)
}

func TestGetMachine_ReadsDeadAndPolicyDerivedNextHeartbeat(t *testing.T) {
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + machineJSONWithFingerprint("mach-1", "fp-abc") + `}`))
	})
	defer closeFn()

	machine, err := c.GetMachine(context.Background(), "mach-1")
	if err != nil {
		t.Fatalf("GetMachine() error = %v", err)
	}
	if gotPath != "/v1/accounts/acct-123/machines/mach-1" {
		t.Errorf("path = %s", gotPath)
	}
	// DEAD is reachable from a read route and must decode, not be
	// normalized away — see HeartbeatStatus.
	if machine.Attributes.HeartbeatStatus != HeartbeatDead {
		t.Errorf("HeartbeatStatus = %q, want DEAD", machine.Attributes.HeartbeatStatus)
	}
	if machine.Attributes.NextHeartbeatAt == nil {
		t.Fatal("NextHeartbeatAt = nil, want the policy-derived timestamp")
	}
}

func TestGetMachine_EscapesTheMachineID(t *testing.T) {
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + machineJSONWithFingerprint("m", "fp") + `}`))
	})
	defer closeFn()

	if _, err := c.GetMachine(context.Background(), "abc/../other"); err != nil {
		t.Fatalf("GetMachine() error = %v", err)
	}
	if gotPath != "/v1/accounts/acct-123/machines/abc%2F..%2Fother" {
		t.Errorf("escaped path = %s", gotPath)
	}
}

func TestListMachines_OffsetPaginationAndFilterWireNames(t *testing.T) {
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + machineJSONWithFingerprint("m1", "fp-1") +
			`],"meta":{"page":{"number":2,"size":25,"total":51,"totalPages":3}}}`))
	})
	defer closeFn()

	page, err := c.ListMachines(context.Background(), ListMachinesOptions{
		LicenseIDs: []string{"lic-a", "lic-b"},
		OwnerIDs:   []string{"own-1"},
		GroupIDs:   []string{"grp-1"},
		Platforms:  []string{"linux", "darwin"},
		Query:      "fp-1",
		Sort:       "-last_heartbeat_at",
		Page:       2,
		PageSize:   25,
	})
	if err != nil {
		t.Fatalf("ListMachines() error = %v", err)
	}

	want := map[string]string{
		"filter[license]":  "lic-a,lic-b",
		"filter[owner]":    "own-1",
		"filter[group]":    "grp-1",
		"filter[platform]": "linux,darwin",
		"filter[q]":        "fp-1",
		"sort":             "-last_heartbeat_at",
		"page[number]":     "2",
		"page[size]":       "25",
	}
	for key, value := range want {
		if got := gotQuery.Get(key); got != value {
			t.Errorf("query[%s] = %q, want %q", key, got, value)
		}
	}
	// A multi-value filter is one comma-joined value, never a repeated
	// key — a repeated key collapses to its last occurrence server-side.
	if n := len(gotQuery["filter[license]"]); n != 1 {
		t.Errorf("filter[license] sent %d times, want 1", n)
	}
	// There is no fingerprint filter on this route. Sending one would be
	// silently ignored and would make FindMachineByFingerprint's
	// client-side equality step look redundant.
	if _, ok := gotQuery["filter[fingerprint]"]; ok {
		t.Error("filter[fingerprint] was sent; the server has no such filter")
	}
	// Offset metadata, not a synthetic keyset cursor.
	if page.Page != (PageMeta{Number: 2, Size: 25, Total: 51, TotalPages: 3}) {
		t.Errorf("Page = %+v", page.Page)
	}
}

func TestListMachines_DefaultsToTheServerMaximumPageSize(t *testing.T) {
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[],"meta":{"page":{"number":1,"size":100,"total":0,"totalPages":0}}}`))
	})
	defer closeFn()

	page, err := c.ListMachines(context.Background(), ListMachinesOptions{})
	if err != nil {
		t.Fatalf("ListMachines() error = %v", err)
	}
	if got := gotQuery.Get("page[size]"); got != "100" {
		t.Errorf("page[size] = %q, want 100 (the server maximum, not its silent 25 default)", got)
	}
	for _, unset := range []string{"page[number]", "sort", "filter[q]", "filter[license]"} {
		if _, ok := gotQuery[unset]; ok {
			t.Errorf("%s was sent for a zero-value ListMachinesOptions", unset)
		}
	}
	if page.Page.TotalPages != 0 {
		t.Errorf("TotalPages = %d, want 0 for an empty result", page.Page.TotalPages)
	}
}

func TestUpdateMachine_EnvelopedBodyOmitsUnsetFields(t *testing.T) {
	var gotBody map[string]any
	var gotMethod string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + machineJSONWithFingerprint("m1", "fp-1") + `}`))
	})
	defer closeFn()

	hostname := "renamed-host"
	cores := int32(8)
	if _, err := c.UpdateMachine(context.Background(), "m1", UpdateMachineOptions{
		Hostname: &hostname,
		Cores:    &cores,
	}); err != nil {
		t.Fatalf("UpdateMachine() error = %v", err)
	}

	if gotMethod != http.MethodPatch {
		t.Errorf("method = %s, want PATCH", gotMethod)
	}
	data, ok := gotBody["data"].(map[string]any)
	if !ok {
		t.Fatalf("body has no JSON:API data envelope: %+v", gotBody)
	}
	if data["type"] != "machines" {
		t.Errorf("data.type = %v", data["type"])
	}
	attrs := data["attributes"].(map[string]any)
	if attrs["hostname"] != "renamed-host" || attrs["cores"] != float64(8) {
		t.Errorf("attributes = %+v", attrs)
	}
	// An unset field is omitted rather than sent as null: the server's
	// COALESCE treats both the same, and omitting keeps the request
	// honest about what it is asking to change.
	for _, key := range []string{"name", "ip", "platform", "memory", "disk", "metadata"} {
		if _, present := attrs[key]; present {
			t.Errorf("attributes[%s] was sent for an unset option", key)
		}
	}
}

func TestFindMachineByFingerprint_RejectsASubstringNearMiss(t *testing.T) {
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		// filter[q] is an ILIKE '%term%', so the server legitimately
		// answers with rows whose fingerprint merely CONTAINS the term.
		_, _ = w.Write([]byte(`{"data":[` +
			machineJSONWithFingerprint("m-long", "fp-abcXX") + `,` +
			machineJSONWithFingerprint("m-case", "FP-ABC") +
			`],"meta":{"page":{"number":1,"size":100,"total":2,"totalPages":1}}}`))
	})
	defer closeFn()

	machine, found, err := c.FindMachineByFingerprint(context.Background(), "lic-1", "fp-abc")
	if err != nil {
		t.Fatalf("FindMachineByFingerprint() error = %v", err)
	}
	if found || machine != nil {
		t.Fatalf("found = %v, machine = %+v; a substring or case-folded hit is not a match", found, machine)
	}
	if got := gotQuery.Get("filter[q]"); got != "fp-abc" {
		t.Errorf("filter[q] = %q", got)
	}
	// The lookup stays scoped to the caller's own license — widening it
	// to the account would adopt another license's seat undetectably.
	if got := gotQuery.Get("filter[license]"); got != "lic-1" {
		t.Errorf("filter[license] = %q, want the caller's license", got)
	}
}

func TestFindMachineByFingerprint_WalksPagesUntilTheExactMatch(t *testing.T) {
	var pages int
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		pages++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		if r.URL.Query().Get("page[number]") == "2" {
			_, _ = w.Write([]byte(`{"data":[` + machineJSONWithFingerprint("m-hit", "fp-abc") +
				`],"meta":{"page":{"number":2,"size":1,"total":2,"totalPages":2}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[` + machineJSONWithFingerprint("m-miss", "xfp-abcx") +
			`],"meta":{"page":{"number":1,"size":1,"total":2,"totalPages":2}}}`))
	})
	defer closeFn()

	machine, found, err := c.FindMachineByFingerprint(context.Background(), "lic-1", "fp-abc")
	if err != nil {
		t.Fatalf("FindMachineByFingerprint() error = %v", err)
	}
	if !found || machine == nil || machine.ID != "m-hit" {
		t.Fatalf("found = %v, machine = %+v", found, machine)
	}
	if pages != 2 {
		t.Errorf("requested %d pages, want 2", pages)
	}
}

func TestFindMachineByFingerprint_StopsOnTheLastPage(t *testing.T) {
	var pages int
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		pages++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + machineJSONWithFingerprint("m", "other") +
			`],"meta":{"page":{"number":1,"size":100,"total":1,"totalPages":1}}}`))
	})
	defer closeFn()

	_, found, err := c.FindMachineByFingerprint(context.Background(), "lic-1", "fp-abc")
	if err != nil {
		t.Fatalf("FindMachineByFingerprint() error = %v", err)
	}
	if found {
		t.Error("found = true")
	}
	if pages != 1 {
		t.Errorf("requested %d pages, want 1 — the walk must stop at totalPages", pages)
	}
}

func TestFindMachineByFingerprint_RefusesABlankFingerprintLocally(t *testing.T) {
	var calls int
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[],"meta":{"page":{"number":1,"size":100,"total":0,"totalPages":0}}}`))
	})
	defer closeFn()

	if _, _, err := c.FindMachineByFingerprint(context.Background(), "lic-1", ""); err == nil {
		t.Fatal("FindMachineByFingerprint(\"\") error = nil; a blank filter[q] is ignored server-side and would list the whole license")
	}
	if calls != 0 {
		t.Errorf("made %d requests, want 0", calls)
	}
}

// idempotentActivationServer wires the three routes
// ActivateMachineIdempotent's recovery path touches.
func idempotentActivationServer(t *testing.T, listBody, validateMeta string) (*Client, func(), *int) {
	t.Helper()
	deletes := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts/acct-123/machines", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/vnd.api+json")
			_, _ = w.Write([]byte(listBody))
			return
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"status":"409","code":"FINGERPRINT_TAKEN","title":"Conflict","detail":"already activated"}]}`))
	})
	mux.HandleFunc("/v1/accounts/acct-123/machines/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes++
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/accounts/acct-123/licenses/lic-1/actions/validate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `,"meta":` + validateMeta + `}`))
	})
	server := httptest.NewServer(mux)
	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c, server.Close, &deletes
}

func TestActivateMachineIdempotent_RecoversTheExistingMachineFromA409(t *testing.T) {
	listBody := `{"data":[` + machineJSONWithFingerprint("m-existing", "fp-abc") +
		`],"meta":{"page":{"number":1,"size":100,"total":1,"totalPages":1}}}`
	c, closeFn, deletes := idempotentActivationServer(t, listBody,
		`{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"ok","code":"VALID"}`)
	defer closeFn()

	machine, meta, err := c.ActivateMachineIdempotent(context.Background(),
		CreateMachineOptions{Fingerprint: "fp-abc", LicenseID: "lic-1"}, nil)
	if err != nil {
		t.Fatalf("ActivateMachineIdempotent() error = %v", err)
	}
	if machine == nil || machine.ID != "m-existing" {
		t.Fatalf("machine = %+v, want the pre-existing row", machine)
	}
	if meta == nil || meta.Code != ValidationCodeValid {
		t.Fatalf("meta = %+v", meta)
	}
	if *deletes != 0 {
		t.Errorf("issued %d deletes; a recovered machine must never be rolled back", *deletes)
	}
}

func TestActivateMachineIdempotent_ReraisesAConflictItCannotResolve(t *testing.T) {
	// The fingerprint is taken on a DIFFERENT license under a wider
	// uniqueness strategy, so a license-scoped search finds nothing.
	listBody := `{"data":[],"meta":{"page":{"number":1,"size":100,"total":0,"totalPages":0}}}`
	c, closeFn, deletes := idempotentActivationServer(t, listBody,
		`{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"ok","code":"VALID"}`)
	defer closeFn()

	machine, meta, err := c.ActivateMachineIdempotent(context.Background(),
		CreateMachineOptions{Fingerprint: "fp-abc", LicenseID: "lic-1"}, nil)
	if !errors.Is(err, ErrFingerprintTaken) {
		t.Fatalf("errors.Is(err, ErrFingerprintTaken) = false, err = %v", err)
	}
	if machine != nil || meta != nil {
		t.Errorf("machine = %+v, meta = %+v; both must be nil on an unresolvable conflict", machine, meta)
	}
	if *deletes != 0 {
		t.Errorf("issued %d deletes", *deletes)
	}
}

func TestActivateMachineIdempotent_DoesNotRollBackARecoveredMachineOnOverage(t *testing.T) {
	listBody := `{"data":[` + machineJSONWithFingerprint("m-existing", "fp-abc") +
		`],"meta":{"page":{"number":1,"size":100,"total":1,"totalPages":1}}}`
	c, closeFn, deletes := idempotentActivationServer(t, listBody,
		`{"ts":"2026-01-01T00:00:00Z","valid":false,"detail":"too many","code":"TOO_MANY_MACHINES"}`)
	defer closeFn()

	machine, meta, err := c.ActivateMachineIdempotent(context.Background(),
		CreateMachineOptions{Fingerprint: "fp-abc", LicenseID: "lic-1"}, nil)
	if !errors.Is(err, ErrMachineOverLimit) {
		t.Fatalf("errors.Is(err, ErrMachineOverLimit) = false, err = %v", err)
	}
	if machine == nil || machine.ID != "m-existing" {
		t.Fatalf("machine = %+v; the caller needs the row it already owns", machine)
	}
	if meta == nil || meta.Code != ValidationCodeTooManyMachines {
		t.Fatalf("meta = %+v", meta)
	}
	// ActivateMachine deletes a machine it just created. This path found
	// a machine it did not create, and deleting it would destroy a seat
	// the license already holds.
	if *deletes != 0 {
		t.Errorf("issued %d deletes; a pre-existing machine must survive an overage verdict", *deletes)
	}
}

func TestActivateMachineIdempotent_PassesThroughANonConflictError(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"status":"401","code":"LICENSE_NOT_ALLOWED","title":"Unauthorized","detail":"nope"}]}`))
	})
	defer closeFn()

	_, _, err := c.ActivateMachineIdempotent(context.Background(),
		CreateMachineOptions{Fingerprint: "fp-abc", LicenseID: "lic-1"}, nil)
	if !errors.Is(err, ErrLicenseNotAllowed) {
		t.Fatalf("errors.Is(err, ErrLicenseNotAllowed) = false, err = %v", err)
	}
}
