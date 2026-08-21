package tamga

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Regression coverage for the server-contract drift audit.
//
// Every error body below is the server's real wire shape, not a
// convenient approximation. In particular JSON:API renders `status` as a
// STRING ("422", not 422) and the codes are the ones the Rust handlers
// actually emit — a fixture that invents either would pass while the SDK
// mismatches production.

const machineLimitExceeded422 = `{"errors":[{"id":"01926b3e-0000-7000-8000-00000000limit","status":"422",` +
	`"code":"MACHINE_LIMIT_EXCEEDED","title":"Unprocessable Entity",` +
	`"detail":"This license has reached its machine limit"}]}`

func TestMapError_MachineLimitExceeded422(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(machineLimitExceeded422))
	})
	defer closeFn()

	_, err := c.CreateMachine(context.Background(), CreateMachineOptions{
		Fingerprint: "fp-1", LicenseID: "lic-id",
	})
	if err == nil {
		t.Fatal("CreateMachine() error = nil, want a 422")
	}
	if !errors.Is(err, ErrMachineLimitExceeded) {
		t.Fatalf("errors.Is(err, ErrMachineLimitExceeded) = false, err = %v", err)
	}
	// Matching is on Code alone, so the four create-time limit sentinels
	// must not alias each other.
	if errors.Is(err, ErrCoreLimitExceeded) || errors.Is(err, ErrMemoryLimitExceeded) ||
		errors.Is(err, ErrDiskLimitExceeded) {
		t.Errorf("MACHINE_LIMIT_EXCEEDED matched a sibling limit sentinel: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(err, &apiErr) = false, err = %v", err)
	}
	if apiErr.HTTPStatus != http.StatusUnprocessableEntity {
		t.Errorf("HTTPStatus = %d, want 422", apiErr.HTTPStatus)
	}
	// JSON:API's status member is a string. Decoding it into an int field
	// would fail outright; this pins the wire type.
	if apiErr.Err.Status != "422" {
		t.Errorf("Err.Status = %q, want the string \"422\"", apiErr.Err.Status)
	}
	if apiErr.Err.Detail != "This license has reached its machine limit" {
		t.Errorf("Err.Detail = %q, want the server's own text", apiErr.Err.Detail)
	}
}

// A raw license key is only accepted when the policy's
// authentication_strategy is LICENSE or MIXED, and that column defaults
// to TOKEN — so this 401 is what a brand-new integration hits on its very
// first call, on every endpoint, until an operator changes the policy.
func TestMapError_LicenseNotAllowed401(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"id":"01926b3e-0000-7000-8000-0000000000au","status":"401",` +
			`"code":"LICENSE_NOT_ALLOWED","title":"Unauthorized",` +
			`"detail":"License key authentication is not allowed for this policy"}]}`))
	})
	defer closeFn()

	_, _, err := c.ValidateByKey(context.Background(), "LIC-KEY")
	if !errors.Is(err, ErrLicenseNotAllowed) {
		t.Fatalf("errors.Is(err, ErrLicenseNotAllowed) = false, err = %v", err)
	}
	// The three license-auth 401s share a status but not a meaning:
	// LICENSE_NOT_ALLOWED is a policy misconfiguration, the other two are
	// license state. Collapsing them would send callers down the wrong
	// remediation path.
	if errors.Is(err, ErrLicenseSuspended) || errors.Is(err, ErrLicenseExpired) ||
		errors.Is(err, ErrUnauthorized) {
		t.Errorf("LICENSE_NOT_ALLOWED matched another 401 sentinel: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(err, &apiErr) = false, err = %v", err)
	}
	if apiErr.HTTPStatus != http.StatusUnauthorized || apiErr.Err.Status != "401" {
		t.Errorf("HTTPStatus = %d, Err.Status = %q, want 401 / \"401\"", apiErr.HTTPStatus, apiErr.Err.Status)
	}
}

// Under a strict policy the machine limit is enforced at creation time,
// so POST /machines 422s and no row is ever written. ActivateMachine must
// short-circuit there: issuing a rollback DELETE would target an ID that
// was never assigned.
func TestActivateMachine_CreateTime422DoesNotDelete(t *testing.T) {
	var deletes, validates atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts/acct-123/machines", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(machineLimitExceeded422))
	})
	mux.HandleFunc("/v1/accounts/acct-123/machines/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/accounts/acct-123/licenses/lic-id/actions/validate", func(w http.ResponseWriter, _ *http.Request) {
		validates.Add(1)
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON +
			`,"meta":{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	machine, meta, err := c.ActivateMachine(context.Background(),
		CreateMachineOptions{Fingerprint: "fp-1", LicenseID: "lic-id"}, nil)

	if !errors.Is(err, ErrMachineOverLimit) {
		t.Fatalf("errors.Is(err, ErrMachineOverLimit) = false, err = %v", err)
	}
	// The underlying *APIError stays in the chain, so a caller who wants
	// to know it was the create-time refusal can still ask.
	if !errors.Is(err, ErrMachineLimitExceeded) {
		t.Errorf("errors.Is(err, ErrMachineLimitExceeded) = false, err = %v", err)
	}
	if machine != nil {
		t.Errorf("machine = %+v, want nil (creation was refused)", machine)
	}
	if meta == nil {
		t.Fatal("meta = nil, want a synthesized ValidationMeta carrying the normalized code")
	}
	// The create-time code is normalized onto the ValidationCode the same
	// limit would produce at validate time, so callers switch on one
	// vocabulary, not two.
	if meta.Code != ValidationCodeTooManyMachines {
		t.Errorf("meta.Code = %q, want TOO_MANY_MACHINES", meta.Code)
	}
	if meta.Valid {
		t.Error("meta.Valid = true, want false")
	}
	if meta.Detail != "This license has reached its machine limit" {
		t.Errorf("meta.Detail = %q, want the server's own detail carried through", meta.Detail)
	}
	if n := deletes.Load(); n != 0 {
		t.Errorf("DELETE was called %d time(s); no machine was created, so there is nothing to roll back", n)
	}
	if n := validates.Load(); n != 0 {
		t.Errorf("validate was called %d time(s); creation already failed, so validation must be skipped", n)
	}
}

func TestActivateMachine_NormalizesEveryCreateTimeLimitCode(t *testing.T) {
	cases := []struct {
		wireCode string
		want     ValidationCode
	}{
		{"MACHINE_LIMIT_EXCEEDED", ValidationCodeTooManyMachines},
		{"CORE_LIMIT_EXCEEDED", ValidationCodeTooManyCores},
		{"MEMORY_LIMIT_EXCEEDED", ValidationCodeTooMuchMemory},
		{"DISK_LIMIT_EXCEEDED", ValidationCodeTooMuchDisk},
	}
	for _, tc := range cases {
		t.Run(tc.wireCode, func(t *testing.T) {
			c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", contentTypeJSONAPI)
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"errors":[{"status":"422","code":"` + tc.wireCode +
					`","title":"Unprocessable Entity","detail":"over limit"}]}`))
			})
			defer closeFn()

			_, meta, err := c.ActivateMachine(context.Background(),
				CreateMachineOptions{Fingerprint: "fp-1", LicenseID: "lic-id"}, nil)
			if !errors.Is(err, ErrMachineOverLimit) {
				t.Fatalf("errors.Is(err, ErrMachineOverLimit) = false, err = %v", err)
			}
			if meta == nil || meta.Code != tc.want {
				t.Fatalf("meta = %+v, want Code = %s", meta, tc.want)
			}
		})
	}
}

// A non-limit create failure must propagate untouched — FINGERPRINT_TAKEN
// means "already activated, carry on", and dressing it up as an
// over-limit error would tell the customer to buy seats they already own.
func TestActivateMachine_NonLimitCreateErrorPropagates(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"status":"409","code":"FINGERPRINT_TAKEN","title":"Conflict",` +
			`"detail":"This fingerprint is already activated within the policy's uniqueness scope"}]}`))
	})
	defer closeFn()

	machine, meta, err := c.ActivateMachine(context.Background(),
		CreateMachineOptions{Fingerprint: "fp-1", LicenseID: "lic-id"}, nil)
	if !errors.Is(err, ErrFingerprintTaken) {
		t.Fatalf("errors.Is(err, ErrFingerprintTaken) = false, err = %v", err)
	}
	if errors.Is(err, ErrMachineOverLimit) {
		t.Error("a 409 FINGERPRINT_TAKEN must not be reported as an over-limit activation")
	}
	if machine != nil || meta != nil {
		t.Errorf("machine = %+v, meta = %+v, want both nil", machine, meta)
	}
}

// The create-time check runs through the policy's overage strategy, so a
// permissive policy (ALLOW_1_25X_OVERAGE, ALWAYS_ALLOW_OVERAGE) still
// creates the machine and only reports the overage at validate time. That
// is the path the rollback-delete exists for, and it must keep working.
func TestActivateMachine_OverageStrategyStillRollsBack(t *testing.T) {
	var deletes atomic.Int32
	var created atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts/acct-123/machines", func(w http.ResponseWriter, _ *http.Request) {
		// Creation succeeds: under ALLOW_1_25X_OVERAGE the server's
		// create-time limit check permits the extra machine.
		created.Store(true)
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
	})
	mux.HandleFunc("/v1/accounts/acct-123/machines/mach-id", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("unexpected %s on the machine item route", r.Method)
		}
		deletes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/accounts/acct-123/licenses/lic-id/actions/validate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON +
			`,"meta":{"ts":"2026-01-01T00:00:00Z","valid":false,` +
			`"detail":"too many machines","code":"TOO_MANY_MACHINES"}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	machine, meta, err := c.ActivateMachine(context.Background(),
		CreateMachineOptions{Fingerprint: "fp-1", LicenseID: "lic-id"}, nil)

	if !created.Load() {
		t.Fatal("the machine was never created; this test must exercise the create-then-validate path")
	}
	if !errors.Is(err, ErrMachineOverLimit) {
		t.Fatalf("errors.Is(err, ErrMachineOverLimit) = false, err = %v", err)
	}
	if machine != nil {
		t.Errorf("machine = %+v, want nil (it was deleted on rollback)", machine)
	}
	if meta == nil || meta.Code != ValidationCodeTooManyMachines {
		t.Fatalf("meta = %+v, want Code = TOO_MANY_MACHINES", meta)
	}
	if n := deletes.Load(); n != 1 {
		t.Errorf("DELETE called %d time(s), want exactly 1 — the created row must be rolled back", n)
	}
}

// The machine heartbeat lives at /actions/ping-heartbeat, which does not
// end in /actions/ping, so it needs its own suffix entry. A dropped 429
// here is not a visible failure — it is a machine that silently slides
// into HeartbeatDead (and, under a require_heartbeat policy, is
// eventually culled).
func TestIsRetryable_HeartbeatActionsAreRetryable(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/v1/accounts/acc/machines/m-1/actions/ping-heartbeat", true},
		{"/v1/accounts/acc/machines/m-1/actions/reset-heartbeat", true},
		{"/v1/accounts/acc/processes/p-1/actions/ping", true},
		{"/v1/accounts/acc/machines", false},
	}
	for _, tc := range cases {
		if got := isRetryable(http.MethodPost, tc.path); got != tc.want {
			t.Errorf("isRetryable(POST, %q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestPingHeartbeat_RetriesAfter429(t *testing.T) {
	var calls atomic.Int32
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
	})
	defer closeFn()

	if _, err := c.PingHeartbeat(context.Background(), "mach-id"); err != nil {
		t.Fatalf("PingHeartbeat() error = %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("calls = %d, want 2 (one throttled, one retry)", n)
	}
}

// Without a deadline a request against a black-holed connection parks a
// heartbeat goroutine forever, and the machine quietly stops pinging.
func TestNew_AppliesADefaultRequestDeadline(t *testing.T) {
	c, err := New("acct-123", WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c.httpClient.Timeout != DefaultTimeout {
		t.Errorf("httpClient.Timeout = %v, want %v", c.httpClient.Timeout, DefaultTimeout)
	}
	// Deliberately longer than the server's own 30s timeout so a slow
	// call surfaces as the server's 504 (which carries an X-Request-Id)
	// rather than racing it to a local deadline error.
	if DefaultTimeout <= 30*time.Second {
		t.Errorf("DefaultTimeout = %v, want > 30s so it does not race the server's own timeout", DefaultTimeout)
	}
}
