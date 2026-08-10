package tamga

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNew_RequiresAccountID(t *testing.T) {
	if _, err := New("", WithLicenseKey("lic-abc")); err == nil {
		t.Fatal("expected an error for empty accountID, got nil")
	}
}

func TestNew_RequiresAuthTransport(t *testing.T) {
	if _, err := New("acct-123"); err == nil {
		t.Fatal("expected an error when no auth transport is configured, got nil")
	}
}

func TestNew_DefaultsBaseURLAndAPIVersion(t *testing.T) {
	c, err := New("acct-123", WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c.baseURL != defaultBaseURL {
		t.Fatalf("baseURL = %q, want %q", c.baseURL, defaultBaseURL)
	}
	if c.apiVersion != DefaultAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", c.apiVersion, DefaultAPIVersion)
	}
}

func TestWithBaseURL_TrimsTrailingSlash(t *testing.T) {
	c, err := New("acct-123", WithLicenseKey("lic-abc"), WithBaseURL("https://api.example.com/"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c.baseURL != "https://api.example.com" {
		t.Fatalf("baseURL = %q, want %q", c.baseURL, "https://api.example.com")
	}
}

// TestAuthTransportTable is a table-driven test per auth transport
// (Bearer / Basic x3 sub-forms / License / Cookie / query param) asserting
// exact header/query wire format on an outgoing request, per
// docs/plans/tamga-go.plan.md Section B.
func TestAuthTransportTable(t *testing.T) {
	tests := []struct {
		name       string
		auth       AuthTransport
		wantHeader string // "" if not header-based
		wantQuery  string // "" if not query-based
		wantCookie string // "" if not cookie-based
	}{
		{name: "bearer", auth: BearerAuth{Token: "tok-1"}, wantHeader: "Bearer tok-1"},
		{name: "basic_email_password", auth: NewBasicAuthEmailPassword("a@b.com", "pw"), wantHeader: "Basic " + "YUBiLmNvbTpwdw=="},
		{name: "basic_token", auth: NewBasicAuthToken("tok-1"), wantHeader: "Basic " + "dG9rLTE6"},
		{name: "basic_license_key", auth: NewBasicAuthLicenseKey("lic-1"), wantHeader: "Basic " + "bGljZW5zZTpsaWMtMQ=="},
		{name: "license_key", auth: LicenseKeyAuth{Key: "lic-1"}, wantHeader: "License lic-1"},
		{name: "session_cookie", auth: SessionCookieAuth{SessionID: "sess-1"}, wantCookie: "sess-1"},
		{name: "query_param", auth: QueryParamAuth{Token: "tok-1"}, wantQuery: "tok-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedReq *http.Request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedReq = r
				w.Header().Set("Content-Type", "application/vnd.api+json")
				_, _ = w.Write([]byte(`{"data":{"id":"lic-id","type":"licenses","attributes":{"status":"ACTIVE","uses":0,"encrypted":false,"strict":false,"floating":false,"machines_count":0,"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
			}))
			defer server.Close()

			c, err := New("acct-123", WithBaseURL(server.URL), WithAuth(tt.auth))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := c.CheckIn(context.Background(), "lic-id"); err != nil {
				t.Fatalf("CheckIn() error = %v", err)
			}
			if capturedReq == nil {
				t.Fatal("server never received a request")
			}
			if tt.wantHeader != "" {
				if got := capturedReq.Header.Get("Authorization"); got != tt.wantHeader {
					t.Errorf("Authorization = %q, want %q", got, tt.wantHeader)
				}
			}
			if tt.wantQuery != "" {
				if got := capturedReq.URL.Query().Get("token"); got != tt.wantQuery {
					t.Errorf("token query param = %q, want %q", got, tt.wantQuery)
				}
			}
			if tt.wantCookie != "" {
				cookie, err := capturedReq.Cookie("Tamga-Session")
				if err != nil {
					t.Fatalf("expected Tamga-Session cookie: %v", err)
				}
				if cookie.Value != tt.wantCookie {
					t.Errorf("cookie value = %q, want %q", cookie.Value, tt.wantCookie)
				}
			}
		})
	}
}

func TestTamgaVersionHeader_DefaultVsOverride(t *testing.T) {
	tests := []struct {
		name string
		want string
		opts []Option
	}{
		{name: "default", opts: nil, want: DefaultAPIVersion},
		{name: "override", opts: []Option{WithAPIVersion("2.0")}, want: "2.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("Tamga-Version")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"ok","code":"VALID"}`))
			}))
			defer server.Close()

			opts := append([]Option{WithBaseURL(server.URL), WithLicenseKey("lic-abc")}, tt.opts...)
			c, err := New("acct-123", opts...)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := c.QuickValidate(context.Background(), "lic-id"); err != nil {
				t.Fatalf("QuickValidate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Tamga-Version = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTamgaOTPHeader_PresenceAndAbsence(t *testing.T) {
	tests := []struct {
		name    string
		otp     string
		wantSet bool
	}{
		{name: "absent_by_default", otp: "", wantSet: false},
		{name: "present_when_configured", otp: "123456", wantSet: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotHeader string
			var hadHeader bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader, hadHeader = r.Header.Get("Tamga-OTP"), r.Header.Get("Tamga-OTP") != ""
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"ok","code":"VALID"}`))
			}))
			defer server.Close()

			opts := []Option{WithBaseURL(server.URL), WithLicenseKey("lic-abc")}
			if tt.otp != "" {
				opts = append(opts, WithOTP(tt.otp))
			}
			c, err := New("acct-123", opts...)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := c.QuickValidate(context.Background(), "lic-id"); err != nil {
				t.Fatalf("QuickValidate() error = %v", err)
			}
			if hadHeader != tt.wantSet {
				t.Errorf("Tamga-OTP present = %v, want %v", hadHeader, tt.wantSet)
			}
			if tt.wantSet && gotHeader != tt.otp {
				t.Errorf("Tamga-OTP = %q, want %q", gotHeader, tt.otp)
			}
		})
	}
}

func TestResponseHeaderParsing_OnAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Tamga-Version", "1.8")
		w.Header().Set("Tamga-Edition", "CE")
		w.Header().Set("Tamga-Mode", "multiplayer")
		w.Header().Set("X-Request-Id", "req-abc")
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"404","code":"NOT_FOUND","title":"Not Found","detail":"no such license"}]}`))
	}))
	defer server.Close()

	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = c.CheckIn(context.Background(), "missing-id")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Response.TamgaVersion != "1.8" || apiErr.Response.TamgaEdition != "CE" ||
		apiErr.Response.TamgaMode != "multiplayer" || apiErr.Response.RequestID != "req-abc" {
		t.Fatalf("Response = %+v, missing expected header values", apiErr.Response)
	}
}

func TestQuickValidate_FlatJSONNoDataEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/actions/validate") {
			t.Errorf("path = %s, want it to contain /actions/validate", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}`))
	}))
	defer server.Close()

	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	meta, err := c.QuickValidate(context.Background(), "lic-id")
	if err != nil {
		t.Fatalf("QuickValidate() error = %v", err)
	}
	if !meta.Valid || meta.Code != ValidationCodeValid || meta.Detail != "is valid" {
		t.Fatalf("meta = %+v, unexpected", meta)
	}
}

func TestAccountIDPathSegment_AlwaysPresent(t *testing.T) {
	tests := []struct {
		name      string
		accountID string
	}{
		{name: "uuid_like", accountID: "01926b3e-0000-7000-8000-000000000000"},
		{name: "account_code", accountID: "acme-corp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"ok","code":"VALID"}`))
			}))
			defer server.Close()

			c, err := New(tt.accountID, WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := c.QuickValidate(context.Background(), "lic-id"); err != nil {
				t.Fatalf("QuickValidate() error = %v", err)
			}
			wantPrefix := "/v1/accounts/" + tt.accountID
			if !strings.HasPrefix(gotPath, wantPrefix) {
				t.Errorf("path = %q, want prefix %q", gotPath, wantPrefix)
			}
		})
	}
}

// TestSubResourceIDsAreEscapedInRequestPaths is the regression guard for
// a real HIGH-severity finding from code review: a licenseID/machineID/
// entitlementID/processID containing URL-meaningful characters
// ('/', '?', '#') must not be able to redirect the request to a different
// path or inject extra query parameters. Every ID this package embeds in
// a request path must go through escapePathSegment (client.go), the same
// treatment accountID already gets via url.PathEscape in buildURL.
func TestSubResourceIDsAreEscapedInRequestPaths(t *testing.T) {
	const maliciousID = "abc?injected=1&other=2"

	var gotPath, gotRawQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"ok","code":"VALID"}`))
	}))
	defer server.Close()

	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := c.QuickValidate(context.Background(), maliciousID); err != nil {
		t.Fatalf("QuickValidate() error = %v", err)
	}

	// The '?' and '&' must have been percent-encoded into the path
	// segment itself, never split out into an actual query string that
	// could inject unintended parameters.
	if gotRawQuery != "" {
		t.Fatalf("request query = %q, want empty — the malicious ID's '?'/'&' must be percent-encoded into the path, not parsed as a real query string", gotRawQuery)
	}
	wantPathSuffix := "/actions/validate"
	if !strings.HasSuffix(gotPath, wantPathSuffix) {
		t.Fatalf("path = %q, want it to end with %q (the ID must not have redirected the request elsewhere)", gotPath, wantPathSuffix)
	}
	if !strings.Contains(gotPath, "abc") {
		t.Fatalf("path = %q, want it to still contain the escaped ID", gotPath)
	}
}

// TestMapError_FallbackOnNonJSONBody covers mapError's fallback branch for
// a non-2xx response whose body isn't valid JSON at all (e.g. an HTML
// error page from a proxy in front of the API) — must produce a synthetic
// "UNKNOWN" error, not panic or silently swallow the failure.
func TestMapError_FallbackOnNonJSONBody(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
	})
	defer closeFn()

	_, err := c.CheckIn(context.Background(), "lic-id")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Err.Code != "UNKNOWN" {
		t.Errorf("Code = %q, want UNKNOWN", apiErr.Err.Code)
	}
	if apiErr.HTTPStatus != http.StatusBadGateway {
		t.Errorf("HTTPStatus = %d, want %d", apiErr.HTTPStatus, http.StatusBadGateway)
	}
}

// TestMapError_FallbackOnEmptyErrorsArray covers mapError's fallback
// branch for a non-2xx response that IS valid JSON:API shape but whose
// "errors" array is empty — same synthetic "UNKNOWN" fallback as a
// non-JSON body, since there's no per-error detail to surface.
func TestMapError_FallbackOnEmptyErrorsArray(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":[]}`))
	})
	defer closeFn()

	_, err := c.CheckIn(context.Background(), "lic-id")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Err.Code != "UNKNOWN" {
		t.Errorf("Code = %q, want UNKNOWN", apiErr.Err.Code)
	}
}

// failingReadCloser is an io.ReadCloser whose Read always errors — used to
// exercise mapError's readErr != nil branch, which a well-behaved
// httptest server can't trigger on its own (a real HTTP body read only
// fails on genuine transport-level problems, like a connection dropped
// mid-body).
type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failingReadCloser) Close() error             { return nil }

func TestMapError_FallbackOnBodyReadError(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     http.Header{},
		Body:       failingReadCloser{},
	}
	err := mapError(resp)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Err.Code != "UNKNOWN" {
		t.Errorf("Code = %q, want UNKNOWN", apiErr.Err.Code)
	}
	if !strings.Contains(apiErr.Err.Detail, "could not be read") {
		t.Errorf("Detail = %q, want it to mention the read failure", apiErr.Err.Detail)
	}
}
