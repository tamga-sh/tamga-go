package tamga

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerAuth_Apply(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	BearerAuth{Token: "tok-abc123"}.Apply(req)
	if got := req.Header.Get("Authorization"); got != "Bearer tok-abc123" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer tok-abc123")
	}
}

func TestLicenseKeyAuth_Apply(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	LicenseKeyAuth{Key: "lic-xyz789"}.Apply(req)
	if got := req.Header.Get("Authorization"); got != "License lic-xyz789" {
		t.Fatalf("Authorization = %q, want %q", got, "License lic-xyz789")
	}
}

func TestQueryParamAuth_Apply(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	QueryParamAuth{Token: "tok-abc123"}.Apply(req)
	if req.Header.Get("Authorization") != "" {
		t.Fatalf("expected no Authorization header, got %q", req.Header.Get("Authorization"))
	}
	if got := req.URL.Query().Get("token"); got != "tok-abc123" {
		t.Fatalf("token query param = %q, want %q", got, "tok-abc123")
	}
}

func TestSessionCookieAuth_Apply(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	SessionCookieAuth{SessionID: "sess-uuid"}.Apply(req)
	cookie, err := req.Cookie("Tamga-Session")
	if err != nil {
		t.Fatalf("expected Tamga-Session cookie, got error: %v", err)
	}
	if cookie.Value != "sess-uuid" {
		t.Fatalf("cookie value = %q, want %q", cookie.Value, "sess-uuid")
	}
}

func TestBasicAuth_Apply(t *testing.T) {
	tests := []struct {
		name  string
		basic BasicAuth
		want  string // base64(user:pass), verified against a known-good encoding
	}{
		{
			name:  "email_password",
			basic: NewBasicAuthEmailPassword("user@example.com", "hunter2"),
			want:  "dXNlckBleGFtcGxlLmNvbTpodW50ZXIy", // base64("user@example.com:hunter2")
		},
		{
			name:  "token_empty_password",
			basic: NewBasicAuthToken("tok-abc123"),
			want:  "dG9rLWFiYzEyMzo=", // base64("tok-abc123:")
		},
		{
			name:  "license_key",
			basic: NewBasicAuthLicenseKey("lic-xyz789"),
			want:  "bGljZW5zZTpsaWMteHl6Nzg5", // base64("license:lic-xyz789")
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			tt.basic.Apply(req)
			want := "Basic " + tt.want
			if got := req.Header.Get("Authorization"); got != want {
				t.Fatalf("Authorization = %q, want %q", got, want)
			}
		})
	}
}

// TestDefaultTransportIsLicenseKeyFirst asserts the SDK's own default
// transport (via WithLicenseKey, New's primary auth shorthand) is
// License-key-first — independent of the server's documented Bearer-first
// try-order (Tamga API protocol specification §1).
func TestDefaultTransportIsLicenseKeyFirst(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"ok","code":"VALID"}`))
	}))
	defer server.Close()

	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-default"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := c.QuickValidate(context.Background(), "lic-id"); err != nil {
		t.Fatalf("QuickValidate() error = %v", err)
	}
	if !strings.HasPrefix(gotAuth, "License ") {
		t.Fatalf("Authorization = %q, want a License-prefixed default transport", gotAuth)
	}
}

func TestSanitizeVersion(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"keeps_allowed_chars", "1.8", "1.8"},
		{"keeps_dash_and_dot", "v1.0-beta", "v1.0-beta"},
		{"strips_disallowed_chars", "1.8; DROP TABLE", "1.8DROPTABLE"},
		{"strips_slashes_and_spaces", "a/b c", "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeVersion(tt.in); got != tt.want {
				t.Fatalf("sanitizeVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeVersion_TruncatesTo32Chars(t *testing.T) {
	long := strings.Repeat("a", 50)
	got := sanitizeVersion(long)
	if len(got) != 32 {
		t.Fatalf("len(sanitizeVersion(...)) = %d, want 32", len(got))
	}
	if got != strings.Repeat("a", 32) {
		t.Fatalf("sanitizeVersion truncation produced unexpected content: %q", got)
	}
}

func TestResponseInfoFromHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Tamga-Version", "1.8")
	h.Set("Tamga-Edition", "CE")
	h.Set("Tamga-Mode", "multiplayer")
	h.Set("X-Request-Id", "req-123")

	info := ResponseInfoFromHeader(h)
	want := ResponseInfo{TamgaVersion: "1.8", TamgaEdition: "CE", TamgaMode: "multiplayer", RequestID: "req-123"}
	if info != want {
		t.Fatalf("ResponseInfoFromHeader() = %+v, want %+v", info, want)
	}
}

func TestResponseInfoFromHeader_MissingHeadersDefaultToEmpty(t *testing.T) {
	info := ResponseInfoFromHeader(http.Header{})
	if info != (ResponseInfo{}) {
		t.Fatalf("ResponseInfoFromHeader(empty) = %+v, want zero value", info)
	}
}
