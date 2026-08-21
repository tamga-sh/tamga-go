package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// deadClient points at a server that has already been shut down, so every
// request fails at the transport layer rather than with an HTTP status.
func deadClient(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	c, err := New("acct-123", WithBaseURL(url), WithLicenseKey("lic-abc"), WithMaxRetries(0))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

// notFoundClient answers every request with a JSON:API 404.
func notFoundClient(t *testing.T) (*Client, func()) {
	t.Helper()
	return newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"status":"404","code":"NOT_FOUND","title":"Not Found","detail":"gone"}]}`))
	})
}

// Every new read must surface a server error rather than a zero value —
// a nil-object-on-404 would look like an empty but valid resource.
func TestNewReadRoutes_PropagateAServerError(t *testing.T) {
	c, closeFn := notFoundClient(t)
	defer closeFn()
	ctx := context.Background()

	t.Run("GetMachine", func(t *testing.T) {
		machine, err := c.GetMachine(ctx, "m1")
		if !errors.Is(err, ErrNotFound) || machine != nil {
			t.Fatalf("machine = %+v, err = %v", machine, err)
		}
	})
	t.Run("ListMachines", func(t *testing.T) {
		page, err := c.ListMachines(ctx, ListMachinesOptions{})
		if !errors.Is(err, ErrNotFound) || page != nil {
			t.Fatalf("page = %+v, err = %v", page, err)
		}
	})
	t.Run("UpdateMachine", func(t *testing.T) {
		machine, err := c.UpdateMachine(ctx, "m1", UpdateMachineOptions{})
		if !errors.Is(err, ErrNotFound) || machine != nil {
			t.Fatalf("machine = %+v, err = %v", machine, err)
		}
	})
	t.Run("ListMachineProcesses", func(t *testing.T) {
		page, err := c.ListMachineProcesses(ctx, "m1", ListOptions{})
		if !errors.Is(err, ErrNotFound) || page != nil {
			t.Fatalf("page = %+v, err = %v", page, err)
		}
	})
	t.Run("GetLicense", func(t *testing.T) {
		license, err := c.GetLicense(ctx, "lic-1")
		if !errors.Is(err, ErrNotFound) || license != nil {
			t.Fatalf("license = %+v, err = %v", license, err)
		}
	})
	t.Run("GetLicensePolicy", func(t *testing.T) {
		policy, err := c.GetLicensePolicy(ctx, "lic-1")
		if !errors.Is(err, ErrNotFound) || policy != nil {
			t.Fatalf("policy = %+v, err = %v", policy, err)
		}
	})
	t.Run("FindMachineByFingerprint", func(t *testing.T) {
		machine, found, err := c.FindMachineByFingerprint(ctx, "lic-1", "fp")
		if !errors.Is(err, ErrNotFound) || found || machine != nil {
			t.Fatalf("machine = %+v, found = %v, err = %v", machine, found, err)
		}
	})
}

func TestGetPolicy_DecodesAPolicyResource(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativePolicyJSON + `}`))
	})
	defer closeFn()

	policy, err := c.GetPolicy(context.Background(), "pol-id")
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if policy.ID != "pol-id" || policy.Attributes.Name != "Standard" {
		t.Errorf("policy = %+v", policy)
	}
	if policy.Attributes.EffectiveHeartbeatWindow() != 90*1e9 {
		t.Errorf("EffectiveHeartbeatWindow() = %v", policy.Attributes.EffectiveHeartbeatWindow())
	}
}

func TestUpdateMachine_SendsEveryOptionItWasGiven(t *testing.T) {
	var gotAttrs map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = decodeInto(r, &body)
		gotAttrs = body["data"].(map[string]any)["attributes"].(map[string]any)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + machineJSONWithFingerprint("m1", "fp") + `}`))
	})
	defer closeFn()

	name, ip, hostname, platform := "n", "10.0.0.2", "h", "windows"
	cores := int32(2)
	memory, disk := int64(4096), int64(8192)
	if _, err := c.UpdateMachine(context.Background(), "m1", UpdateMachineOptions{
		Name: &name, IP: &ip, Hostname: &hostname, Platform: &platform,
		Cores: &cores, Memory: &memory, Disk: &disk,
		Metadata: map[string]any{"env": "prod"},
	}); err != nil {
		t.Fatalf("UpdateMachine() error = %v", err)
	}
	for key, want := range map[string]any{
		"name": "n", "ip": "10.0.0.2", "hostname": "h", "platform": "windows",
		"cores": float64(2), "memory": float64(4096), "disk": float64(8192),
	} {
		if gotAttrs[key] != want {
			t.Errorf("attributes[%s] = %v, want %v", key, gotAttrs[key], want)
		}
	}
	if gotAttrs["metadata"].(map[string]any)["env"] != "prod" {
		t.Errorf("attributes.metadata = %v", gotAttrs["metadata"])
	}
}

func TestFindMachineByFingerprint_StopsBeforeTheServersOffsetCeiling(t *testing.T) {
	var pages int
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		pages++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		// A page size of 100 at page 1001 would ask for offset 100_000,
		// which the server refuses with 400 PAGE_OUT_OF_RANGE. Claim to
		// be exactly at that boundary with more pages still to come.
		_, _ = w.Write([]byte(`{"data":[` + machineJSONWithFingerprint("m", "other") +
			`],"meta":{"page":{"number":1001,"size":100,"total":200000,"totalPages":2000}}}`))
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
		t.Errorf("requested %d pages; the walk must stop rather than provoke PAGE_OUT_OF_RANGE", pages)
	}
}

func TestActivateMachineIdempotent_WrapsALookupFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts/acct-123/machines", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errors":[{"status":"500","code":"INTERNAL_SERVER_ERROR","title":"Boom","detail":"db"}]}`))
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"status":"409","code":"FINGERPRINT_TAKEN","title":"Conflict","detail":"taken"}]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"), WithMaxRetries(0))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, _, err = c.ActivateMachineIdempotent(context.Background(),
		CreateMachineOptions{Fingerprint: "fp", LicenseID: "lic-1"}, nil)
	// Both the original conflict and the lookup failure stay in the
	// chain: the caller needs to know the activation was refused AND why
	// the recovery could not run.
	if !errors.Is(err, ErrFingerprintTaken) {
		t.Errorf("errors.Is(err, ErrFingerprintTaken) = false, err = %v", err)
	}
	if !errors.Is(err, ErrInternal) {
		t.Errorf("errors.Is(err, ErrInternal) = false, err = %v", err)
	}
}

func TestActivateMachineIdempotent_PropagatesAValidateFailureWithTheRecoveredMachine(t *testing.T) {
	listBody := `{"data":[` + machineJSONWithFingerprint("m-existing", "fp-abc") +
		`],"meta":{"page":{"number":1,"size":100,"total":1,"totalPages":1}}}`
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts/acct-123/machines", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(listBody))
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"status":"409","code":"FINGERPRINT_TAKEN","title":"Conflict","detail":"taken"}]}`))
	})
	mux.HandleFunc("/v1/accounts/acct-123/licenses/lic-1/actions/validate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"status":"401","code":"LICENSE_SUSPENDED","title":"Unauthorized","detail":"suspended"}]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"), WithMaxRetries(0))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	machine, meta, err := c.ActivateMachineIdempotent(context.Background(),
		CreateMachineOptions{Fingerprint: "fp-abc", LicenseID: "lic-1"}, nil)
	if !errors.Is(err, ErrLicenseSuspended) {
		t.Fatalf("errors.Is(err, ErrLicenseSuspended) = false, err = %v", err)
	}
	// A failed validate call is not a verdict about the machine, so the
	// row that was found is handed back rather than discarded — the same
	// reasoning ActivateMachine applies to a machine it just created.
	if machine == nil || machine.ID != "m-existing" {
		t.Errorf("machine = %+v", machine)
	}
	if meta != nil {
		t.Errorf("meta = %+v, want nil when no verdict was reached", meta)
	}
}

func TestNewCalls_SurfaceATransportFailure(t *testing.T) {
	c := deadClient(t)
	ctx := context.Background()

	if _, err := c.Health(ctx); err == nil {
		t.Error("Health() error = nil against a dead server")
	}
	if _, _, err := c.CheckUpgrade(ctx, UpgradeOptions{
		ProductID: "p", Platform: "darwin", Filetype: "dmg", Version: "1.0.0",
	}); err == nil {
		t.Error("CheckUpgrade() error = nil against a dead server")
	}
	if _, err := c.GetMachine(ctx, "m1"); err == nil {
		t.Error("GetMachine() error = nil against a dead server")
	}
}

func TestNewCalls_RejectAMalformedSuccessBody(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":`))
	})
	defer closeFn()
	ctx := context.Background()

	if _, err := c.Health(ctx); err == nil {
		t.Error("Health() error = nil for a truncated body")
	}
	if _, _, err := c.CheckUpgrade(ctx, UpgradeOptions{
		ProductID: "p", Platform: "darwin", Filetype: "dmg", Version: "1.0.0",
	}); err == nil {
		t.Error("CheckUpgrade() error = nil for a truncated body")
	}
}

// decodeInto reads a request body as JSON into v.
func decodeInto(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
