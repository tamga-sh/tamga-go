package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c, server.Close
}

const representativeLicenseJSON = `{
	"id":"lic-id","type":"licenses",
	"attributes":{
		"name":"Acme Corp","key":"lic-abc123","status":"ACTIVE","expiry":null,
		"suspended":false,"protected":false,"uses":0,"scheme":null,"encrypted":false,
		"strict":false,"floating":false,"max_machines":null,"max_uses":null,"max_users":null,
		"last_validated_at":null,"last_check_in_at":null,"last_check_out_at":null,
		"machines_count":0,"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"
	}
}`

func TestValidateByKey_RequestResponseRoundTrip(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/licenses/actions/validate-key") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `,"meta":{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}}`))
	})
	defer closeFn()

	license, meta, err := c.ValidateByKey(context.Background(), "lic-abc123")
	if err != nil {
		t.Fatalf("ValidateByKey() error = %v", err)
	}
	if gotBody["key"] != "lic-abc123" {
		t.Errorf("request body key = %v, want lic-abc123", gotBody["key"])
	}
	if license.Attributes.Key == nil || *license.Attributes.Key != "lic-abc123" {
		t.Errorf("license.Attributes.Key = %v", license.Attributes.Key)
	}
	if !meta.Valid || meta.Code != ValidationCodeValid {
		t.Errorf("meta = %+v", meta)
	}
}

func TestValidateByID_FullyPopulatedScope(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `,"meta":{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}}`))
	})
	defer closeFn()

	product := "prod-1"
	policy := "pol-1"
	user := "user-1"
	environment := "env-1"
	fingerprint := "fp-1"
	version := "1.0.0"
	checksum := "abc123"
	scope := &Scope{
		Product: &product, Policy: &policy, User: &user, Environment: &environment,
		Entitlements: []string{"ent-a", "ent-b"}, Fingerprint: &fingerprint,
		Version: &version, Checksum: &checksum,
	}
	_, _, err := c.ValidateByID(context.Background(), "lic-id", &ValidateByIDOptions{Scope: scope})
	if err != nil {
		t.Fatalf("ValidateByID() error = %v", err)
	}
	meta, ok := gotBody["meta"].(map[string]any)
	if !ok {
		t.Fatalf("request body meta missing: %+v", gotBody)
	}
	scopeBody, ok := meta["scope"].(map[string]any)
	if !ok {
		t.Fatalf("request body meta.scope missing: %+v", meta)
	}
	if scopeBody["product"] != "prod-1" || scopeBody["policy"] != "pol-1" ||
		scopeBody["user"] != "user-1" || scopeBody["environment"] != "env-1" ||
		scopeBody["fingerprint"] != "fp-1" || scopeBody["version"] != "1.0.0" || scopeBody["checksum"] != "abc123" {
		t.Errorf("scope body = %+v", scopeBody)
	}
}

func TestValidateByID_SkipTouchTrueFalse(t *testing.T) {
	for _, skipTouch := range []bool{true, false} {
		var gotBody map[string]any
		c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/vnd.api+json")
			_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `,"meta":{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}}`))
		})
		_, _, err := c.ValidateByID(context.Background(), "lic-id", &ValidateByIDOptions{SkipTouch: skipTouch})
		closeFn()
		if err != nil {
			t.Fatalf("ValidateByID() error = %v", err)
		}
		meta := gotBody["meta"].(map[string]any)
		if meta["skip_touch"] != skipTouch {
			t.Errorf("skip_touch = %v, want %v", meta["skip_touch"], skipTouch)
		}
	}
}

func TestValidateByID_NilOptsSendsAbsentBody(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `,"meta":{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}}`))
	})
	defer closeFn()

	_, _, err := c.ValidateByID(context.Background(), "lic-id", nil)
	if err != nil {
		t.Fatalf("ValidateByID() error = %v", err)
	}
	meta := gotBody["meta"].(map[string]any)
	if meta["skip_touch"] != false {
		t.Errorf("skip_touch = %v, want false", meta["skip_touch"])
	}
	if _, present := meta["scope"]; present {
		t.Errorf("expected no scope key when opts is nil, got %+v", meta)
	}
}

func TestQuickValidate_NoDataKeyExpected(t *testing.T) {
	var rawBody []byte
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := []byte(`{"ts":"2026-01-01T00:00:00Z","valid":false,"detail":"expired","code":"EXPIRED"}`)
		rawBody = body
		_, _ = w.Write(body)
	})
	defer closeFn()

	meta, err := c.QuickValidate(context.Background(), "lic-id")
	if err != nil {
		t.Fatalf("QuickValidate() error = %v", err)
	}
	if strings.Contains(string(rawBody), `"data"`) {
		t.Fatal("fixture accidentally contains a data key — test setup bug")
	}
	if meta.Valid || meta.Code != ValidationCodeExpired {
		t.Errorf("meta = %+v", meta)
	}
}

func TestScope_OmitsUnsetFieldsNotNull(t *testing.T) {
	product := "prod-1"
	scope := Scope{Product: &product}
	encoded, err := json.Marshal(scope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(encoded, &m); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("expected exactly 1 key (product), got %+v", m)
	}
	if _, ok := m["product"]; !ok {
		t.Errorf("expected product key, got %+v", m)
	}
}

func TestCheckIn_UpdatesLastCheckInAt(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/actions/check-in") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"lic-id","type":"licenses","attributes":{"status":"ACTIVE","uses":0,"encrypted":false,"strict":false,"floating":false,"machines_count":0,"metadata":{},"last_check_in_at":"2026-02-01T00:00:00Z","created":"2026-01-01T00:00:00Z","updated":"2026-02-01T00:00:00Z"}}}`))
	})
	defer closeFn()

	license, err := c.CheckIn(context.Background(), "lic-id")
	if err != nil {
		t.Fatalf("CheckIn() error = %v", err)
	}
	if license.Attributes.LastCheckInAt == nil || *license.Attributes.LastCheckInAt != "2026-02-01T00:00:00Z" {
		t.Errorf("LastCheckInAt = %v", license.Attributes.LastCheckInAt)
	}
}

func TestCheckIn_CheckInNotRequiredMapsToSentinel(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"422","code":"CHECK_IN_NOT_REQUIRED","title":"Unprocessable Entity","detail":"this license's policy does not require check-in"}]}`))
	})
	defer closeFn()

	_, err := c.CheckIn(context.Background(), "lic-id")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, ErrCheckInNotRequired) {
		t.Fatalf("errors.Is(err, ErrCheckInNotRequired) = false, err = %v", err)
	}
}

// ExampleClient_ValidateByKey demonstrates validating a license by its raw
// key — the simplest way to check a license without knowing its ID. See
// examples/validate/main.go for a full runnable program against a real
// server; this Example runs against a local httptest server so it stays a
// real, executable test with no live network dependency.
func ExampleClient_ValidateByKey() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `,"meta":{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}}`))
	}))
	defer server.Close()

	client, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc123"))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	_, meta, err := client.ValidateByKey(context.Background(), "lic-abc123")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("valid=%v code=%s\n", meta.Valid, meta.Code)
	// Output: valid=true code=VALID
}
