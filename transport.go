package tamga

import (
	"encoding/base64"
	"net/http"
)

// AuthTransport applies one authentication scheme to an outgoing request —
// either a header or a query parameter, matching the server's try-order
// documented in the Tamga API protocol specification §1:
//
//  1. Authorization: Bearer <token>
//  2. Authorization: Basic <base64>  — 3 sub-forms: email:password,
//     token: (token as username, empty password), license:<key>
//  3. Authorization: License <key>   — primary transport for embedded/
//     client SDKs; this SDK's default (see LicenseKeyAuth)
//  4. Cookie: Tamga-Session=<uuid>   — browser/portal only, requires a
//     matching Origin header; implemented here for completeness only
//  5. ?token=/?auth= query parameter
//
// Tokens are opaque strings: the server documents tok-/prod-/env-/activ-/
// lic- prefixes by type, but every issued token actually gets the tok-
// prefix regardless of type today — this package deliberately does not
// build prefix-based type detection against that documented-but-
// unimplemented convention.
type AuthTransport interface {
	// Apply mutates req in place, adding whatever header or query
	// parameter this transport uses to authenticate the request.
	Apply(req *http.Request)
}

// BearerAuth sends Authorization: Bearer <token>.
type BearerAuth struct {
	Token string
}

// Apply implements AuthTransport.
func (a BearerAuth) Apply(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.Token)
}

// BasicAuth sends Authorization: Basic <base64(user:pass)>, in one of the
// three sub-forms the server accepts. Construct via NewBasicAuthEmailPassword,
// NewBasicAuthToken, or NewBasicAuthLicenseKey — the zero value has no
// well-defined wire form.
type BasicAuth struct {
	userPass string
}

// NewBasicAuthEmailPassword builds the base64(email:password) sub-form.
func NewBasicAuthEmailPassword(email, password string) BasicAuth {
	return BasicAuth{userPass: email + ":" + password}
}

// NewBasicAuthToken builds the base64(token:) sub-form — the token as
// username, empty password.
func NewBasicAuthToken(token string) BasicAuth {
	return BasicAuth{userPass: token + ":"}
}

// NewBasicAuthLicenseKey builds the base64(license:<key>) sub-form.
func NewBasicAuthLicenseKey(key string) BasicAuth {
	return BasicAuth{userPass: "license:" + key}
}

// Apply implements AuthTransport.
func (a BasicAuth) Apply(req *http.Request) {
	encoded := base64.StdEncoding.EncodeToString([]byte(a.userPass))
	req.Header.Set("Authorization", "Basic "+encoded)
}

// LicenseKeyAuth sends Authorization: License <key> — the primary
// transport for embedded/client SDKs validating against a raw license key,
// and this SDK's own default (see New in client.go), independent of the
// server's Bearer-first try-order.
//
// ⚠️ Authentication IS enforced, and this transport is conditional on
// server-side configuration. Three things can refuse the key before any
// handler runs, all as a 401:
//
//   - The policy's authentication_strategy must be LICENSE or MIXED.
//     It defaults to TOKEN, under which every request fails
//     LICENSE_NOT_ALLOWED (ErrLicenseNotAllowed). This is the one to
//     check first when a brand-new integration 401s on every call.
//   - A suspended license never authenticates: LICENSE_SUSPENDED
//     (ErrLicenseSuspended).
//   - An expired license authenticates under every expiration strategy
//     except REVOKE_ACCESS, which answers LICENSE_EXPIRED
//     (ErrLicenseExpired).
//
// Past that gate, a license key authenticates as the LicenseToken role,
// which is narrower than a bearer token: ResetHeartbeat and
// GenerateOfflineProof are role-gated above it and always 403 — see their
// doc comments.
type LicenseKeyAuth struct {
	Key string
}

// Apply implements AuthTransport.
func (a LicenseKeyAuth) Apply(req *http.Request) {
	req.Header.Set("Authorization", "License "+a.Key)
}

// SessionCookieAuth sends Cookie: Tamga-Session=<uuid>. Implemented for
// completeness only: this transport is browser/portal-only, requires a
// matching Origin header the server checks against, and is not relevant to
// a non-browser SDK consumer — most callers should use LicenseKeyAuth,
// BearerAuth, or BasicAuth instead.
type SessionCookieAuth struct {
	SessionID string
}

// Apply implements AuthTransport.
func (a SessionCookieAuth) Apply(req *http.Request) {
	// gosec's G124 flags http.Cookie literals missing Secure/HttpOnly/
	// SameSite, a rule meant for server-side Set-Cookie response headers —
	// those attributes have no meaning on an outgoing request's Cookie
	// header (http.Request.AddCookie only ever reads Name/Value), so
	// there's nothing to set here.
	req.AddCookie(&http.Cookie{Name: "Tamga-Session", Value: a.SessionID}) //nolint:gosec // G124 is response-cookie-only; see comment above
}

// QueryParamAuth sends the token as a `?token=` query parameter (the
// server also accepts `?auth=` as a synonym; this transport sends `token`
// since it mirrors the `Bearer <token>` semantics of the transport it
// substitutes for).
type QueryParamAuth struct {
	Token string
}

// Apply implements AuthTransport.
func (a QueryParamAuth) Apply(req *http.Request) {
	q := req.URL.Query()
	q.Set("token", a.Token)
	req.URL.RawQuery = q.Encode()
}

// DefaultAPIVersion is the Tamga-Version header value this SDK sends
// unless overridden via WithAPIVersion. The server's own default is "1.8"
// if the header is omitted entirely, but this SDK never relies on that —
// it always sends an explicit value, pinned per SDK major version, so
// server-side API evolution can't silently change response shapes
// underneath a released SDK version.
const DefaultAPIVersion = "1.8"

// userAgent is the default User-Agent sent for support/debugging purposes,
// even though the server has no requirement or handling for it.
//
// The version here is rewritten in place by release-please on every release —
// the trailing annotation marks the line for its generic updater, which
// replaces the semver-looking token on it. transport.go is registered under
// "extra-files" in release-please-config.json so the updater actually visits
// this file. Do not hand-edit the version or drop the annotation: without it
// the constant silently drifts and misreports the SDK version to the server.
const userAgent = "tamga-go/1.2.3" // x-release-please-version

// sanitizeVersion filters a Tamga-Version header value down to the
// server's accepted character set (alphanumeric plus '.'/'-'), truncated
// to 32 characters, matching the server's own filter-then-truncate
// behavior. Disallowed characters are dropped, not replaced.
func sanitizeVersion(version string) string {
	out := make([]byte, 0, len(version))
	for i := 0; i < len(version) && len(out) < 32; i++ {
		c := version[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-':
			out = append(out, c)
		}
	}
	return string(out)
}

// ResponseInfo carries response headers a caller may want to read off any
// successful response or *APIError for support/debugging purposes.
//
// Deliberately not modeled: Tamga-Environment (no server code path reads
// it yet — planned EE feature) and X-RateLimit-* (declared in the CORS
// allowlist only, never set by any handler).
type ResponseInfo struct {
	// TamgaVersion is the Tamga-Version header echoed back by the server.
	TamgaVersion string
	// TamgaEdition is "EE" or "CE".
	TamgaEdition string
	// TamgaMode is "singleplayer" or "multiplayer".
	TamgaMode string
	// RequestID is X-Request-Id, useful to log for support — correlates a
	// client-side error with server-side logs.
	RequestID string
}

// ResponseInfoFromHeader extracts the known response headers from h.
// Missing headers are left as the empty string rather than causing an
// error — this is diagnostic metadata, not required for correctness.
func ResponseInfoFromHeader(h http.Header) ResponseInfo {
	return ResponseInfo{
		TamgaVersion: h.Get("Tamga-Version"),
		TamgaEdition: h.Get("Tamga-Edition"),
		TamgaMode:    h.Get("Tamga-Mode"),
		RequestID:    h.Get("X-Request-Id"),
	}
}
