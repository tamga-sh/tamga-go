package tamga

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The server rate-limits; the SDK has to cope.
//
// Credential-accepting endpoints run on a tight per-IP budget (5 req/s by
// default), and the calls a licensing client makes on a timer — validate,
// heartbeat ping, check-in — are exactly the ones inside it. Without backoff,
// a retry loop turns one throttled request into a sustained burst that keeps
// the bucket empty and the client never recovers on its own.

func TestDo_RetriesAThrottledValidationThenSucceeds(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", contentTypeJSONAPI)
		_, _ = w.Write([]byte(`{"data":{"id":"lic-id","type":"licenses","attributes":{}},` +
			`"meta":{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}}`))
	}))
	defer srv.Close()

	c, err := New("acc-123", WithBaseURL(srv.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ValidateByKey(context.Background(), "K"); err != nil {
		t.Fatalf("ValidateByKey() error = %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (one throttled, one retry)", calls)
	}
}

func TestDo_DoesNotRetryWhenDisabled(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, _ := New("acc-123", WithBaseURL(srv.URL), WithLicenseKey("lic-abc"), WithMaxRetries(0))
	if _, _, err := c.ValidateByKey(context.Background(), "K"); err == nil {
		t.Fatal("expected an error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 — retries were disabled", calls)
	}
}

func TestIsRetryable_CreatesAreNeverRetried(t *testing.T) {
	// Repeating a create is not safe: the first attempt may well have
	// succeeded server-side, and a second activation burns a second seat.
	if isRetryable(http.MethodPost, "/v1/accounts/acc/machines") {
		t.Error("POST /machines must not be retried")
	}
	if isRetryable(http.MethodPost, "/v1/accounts/acc/licenses") {
		t.Error("POST /licenses must not be retried")
	}
}

func TestIsRetryable_IdempotentCallsAre(t *testing.T) {
	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/accounts/acc/licenses"},
		{http.MethodPost, "/v1/accounts/acc/licenses/actions/validate"},
		{http.MethodPost, "/v1/accounts/acc/machines/x/actions/ping"},
	}
	for _, tc := range cases {
		if !isRetryable(tc.method, tc.path) {
			t.Errorf("%s %s should be retryable", tc.method, tc.path)
		}
	}
}

func TestRetryDelay_CapsAnAbsurdRetryAfter(t *testing.T) {
	// A misconfigured — or hostile — proxy must not be able to park the caller
	// for a day on a single header.
	if got := retryDelay(0, 5, true); got != 5*time.Second {
		t.Errorf("retryDelay(0, 5) = %v, want 5s", got)
	}
	if got := retryDelay(0, 86400, true); got > 60*time.Second {
		t.Errorf("retryDelay(0, 86400) = %v, want <= 60s", got)
	}
}

func TestRetryDelay_GrowsWhenTheServerSaysNothing(t *testing.T) {
	// Guessing the same short delay every time is just the original burst.
	if retryDelay(2, 0, false) <= retryDelay(0, 0, false) {
		t.Error("backoff must grow across attempts")
	}
}
