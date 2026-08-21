package tamga

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHealth_SendsNoCredentialAndNoAccountPrefix(t *testing.T) {
	var gotPath string
	var gotHeaders http.Header
	var gotQuery string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotHeaders, gotQuery = r.URL.Path, r.Header.Clone(), r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"0.9.1","uptime_secs":4210}`))
	})
	defer closeFn()

	health, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}

	// No /v1/accounts/{account_id} prefix — this is the one route that
	// hangs off the configured origin directly.
	if gotPath != "/v1/health" {
		t.Errorf("path = %s, want /v1/health with no account prefix", gotPath)
	}
	// The whole point of this call is that it isolates a transport
	// problem from a credential one, and it cannot do that if it carries
	// a credential: resolution runs before the public-route check, so a
	// suspended or policy-refused license key 401s even here.
	for _, header := range []string{"Authorization", "Cookie", "Tamga-OTP"} {
		if got := gotHeaders.Get(header); got != "" {
			t.Errorf("%s = %q; Health must be sent anonymously", header, got)
		}
	}
	if strings.Contains(gotQuery, "token=") || strings.Contains(gotQuery, "auth=") {
		t.Errorf("query = %q; Health must not carry a query-parameter credential", gotQuery)
	}
	// It still identifies itself.
	if gotHeaders.Get("User-Agent") != userAgent {
		t.Errorf("User-Agent = %q", gotHeaders.Get("User-Agent"))
	}
	if gotHeaders.Get("Tamga-Version") == "" {
		t.Error("Tamga-Version was not sent")
	}

	if health.Status != "ok" || health.Version != "0.9.1" || health.UptimeSecs != 4210 {
		t.Errorf("Health = %+v", health)
	}
}

// The query-parameter transport is the one that would smuggle a
// credential past a header-only assertion.
func TestHealth_IsAnonymousUnderTheQueryParamTransport(t *testing.T) {
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"0.9.1","uptime_secs":1}`))
	}))
	defer server.Close()

	c, err := New("acct-123", WithBaseURL(server.URL), WithAuth(QueryParamAuth{Token: "tok-secret"}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if strings.Contains(gotURL, "tok-secret") {
		t.Errorf("request URL = %q; the token leaked into the health probe", gotURL)
	}
}

func TestHealth_DoesNotGoThroughTheJSONAPIEnvelope(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Flat body, exactly as the handler emits it — no data envelope.
		_, _ = w.Write([]byte(`{"status":"ok","version":"1.4.0","uptime_secs":0}`))
	})
	defer closeFn()

	health, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v; a flat body must decode without a data envelope", err)
	}
	if health.Status != "ok" {
		t.Errorf("Status = %q", health.Status)
	}
}

func TestHealth_SurfacesAnUnhealthyStatusAsAnError(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"errors":[{"status":"503","code":"INTERNAL_SERVER_ERROR","title":"Unavailable","detail":"db down"}]}`))
	})
	defer closeFn()

	if _, err := c.Health(context.Background()); !errors.Is(err, ErrInternal) {
		t.Fatalf("errors.Is(err, ErrInternal) = false, err = %v", err)
	}
}

func TestHealth_IsRetriedOnA429LikeAnyGet(t *testing.T) {
	var calls atomic.Int32
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"1.0.0","uptime_secs":7}`))
	})
	defer closeFn()

	health, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.UptimeSecs != 7 {
		t.Errorf("UptimeSecs = %d", health.UptimeSecs)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("made %d calls, want 2 (one throttled, one retried)", got)
	}
}
