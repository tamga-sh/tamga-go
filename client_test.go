package tamga

import (
	"context"
	"errors"
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
