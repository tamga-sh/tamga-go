package tamga

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultBaseURL is the production Tamga API host, matching the example
// host used consistently across every sibling SDK's README
// (docs/sdk.md gives no single canonical default, but every hand-written
// Tamga SDK's documentation uses "https://api.tamga.sh" as the example —
// this SDK follows that convention as its zero-config default so New only
// strictly requires an account ID and an auth transport).
const defaultBaseURL = "https://api.tamga.sh"

// Client is the Tamga API client. Every public method takes
// context.Context as its first argument. Construct with New.
type Client struct {
	auth         AuthTransport
	httpClient   *http.Client
	entCache     *entitlementCache
	accountID    string
	baseURL      string
	apiVersion   string
	otp          string
	maxRetries   int
	entCacheOnce sync.Once
}

// Option configures a Client constructed via New.
type Option func(*Client)

// WithBaseURL overrides the default API host
// ("https://api.tamga.sh"). A trailing slash, if present, is trimmed.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithHTTPClient overrides the default *http.Client used to send requests
// (http.DefaultClient's zero value otherwise). Useful for custom timeouts,
// transports, or test doubles.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithAPIVersion overrides the Tamga-Version header this SDK sends on
// every request (default DefaultAPIVersion). Pin this per SDK major
// version so server-side API evolution can't silently change response
// shapes underneath a released SDK version.
func WithAPIVersion(version string) Option {
	return func(c *Client) { c.apiVersion = version }
}

// WithOTP sets the Tamga-OTP header sent on every authenticated request,
// for accounts with 2FA enabled on the credential's bearer.
func WithOTP(code string) Option {
	return func(c *Client) { c.otp = code }
}

// WithLicenseKey configures the LicenseKeyAuth transport
// (Authorization: License <key>) — the primary transport for embedded/
// client SDKs and this SDK's own default authentication path. Equivalent
// to WithAuth(LicenseKeyAuth{Key: key}); prefer this shorthand unless a
// different transport (Bearer/Basic/Cookie/query-param) is required.
func WithLicenseKey(key string) Option {
	return func(c *Client) { c.auth = LicenseKeyAuth{Key: key} }
}

// WithAuth overrides the transport used to authenticate every request.
// Use this for any of the four non-default transports (BearerAuth,
// BasicAuth, SessionCookieAuth, QueryParamAuth); for the SDK's default
// license-key transport, WithLicenseKey is a shorthand for the equivalent
// WithAuth(LicenseKeyAuth{Key: key}).
func WithAuth(auth AuthTransport) Option {
	return func(c *Client) { c.auth = auth }
}

// New builds a Client for the given account ID. An auth transport is
// required — pass WithLicenseKey (the SDK's default, primary transport for
// embedded/client SDKs) or WithAuth for any other transport; New returns
// an error if neither option was supplied.
//
// The {account_id} path segment is required on every request in both
// singleplayer and multiplayer server modes (docs/sdk.md §1) — there is no
// mode where it can be omitted, so it is a required positional argument
// here rather than an Option.
func New(accountID string, opts ...Option) (*Client, error) {
	if accountID == "" {
		return nil, fmt.Errorf("tamga: accountID must not be empty")
	}
	c := &Client{
		accountID:  accountID,
		baseURL:    defaultBaseURL,
		httpClient: http.DefaultClient,
		apiVersion: DefaultAPIVersion,
		maxRetries: DefaultMaxRetries,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.auth == nil {
		return nil, fmt.Errorf("tamga: an auth transport is required — pass WithLicenseKey or WithAuth")
	}
	return c, nil
}

// contentTypeJSONAPI is the default Content-Type for every JSON:API
// request/response in this package, except quick-validate's flat-JSON
// special case (docs/sdk.md §1).
const contentTypeJSONAPI = "application/vnd.api+json"

// DefaultMaxRetries is how many times a rate-limited (429) request is retried
// before giving up.
//
// Three rides out a short burst without turning a sustained 429 into a request
// that hangs for minutes.
const DefaultMaxRetries = 3

// WithMaxRetries overrides how many times a rate-limited request is retried.
//
// Pass 0 to handle 429 yourself — the returned *APIError still reports the
// status, and the server's Retry-After is available on the response.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n < 0 {
			n = 0
		}
		c.maxRetries = n
	}
}

// buildURL joins the configured base URL, the required
// /v1/accounts/{account_id} prefix, and path into a full request URL.
// account_id is path-escaped since it may be either a UUID or an
// account-code-style string (docs/sdk.md §1 — both forms are valid and
// this segment is always present regardless of which form is used).
func (c *Client) buildURL(path string) string {
	return c.baseURL + "/v1/accounts/" + url.PathEscape(c.accountID) + path
}

// escapePathSegment escapes id for safe interpolation into a request path
// (e.g. fmt.Sprintf("/licenses/%s/actions/validate", escapePathSegment(licenseID))).
// Every resource/relationship ID this package accepts from a caller
// (license/machine/entitlement/component/process IDs) MUST be passed
// through this before being embedded in a path — an unescaped ID
// containing '/', '?', '#', or other URL-meaningful characters could
// otherwise redirect the request to a different path or inject query
// parameters (e.g. a licenseID of "abc/../other-account/licenses" or
// "abc?foo=bar"). accountID gets the same treatment via url.PathEscape
// directly in buildURL above; this is the equivalent for every other ID
// this package builds paths from.
func escapePathSegment(id string) string {
	return url.PathEscape(id)
}

// newRequest builds an *http.Request against path with the configured
// auth transport, Tamga-Version, Tamga-OTP (if set), and User-Agent
// applied. body, if non-nil, is JSON-marshaled and sent with
// Content-Type: application/vnd.api+json.
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("tamga: encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.buildURL(path), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("tamga: build request: %w", err)
	}
	c.auth.Apply(req)
	req.Header.Set("Tamga-Version", sanitizeVersion(c.apiVersion))
	if c.otp != "" {
		req.Header.Set("Tamga-OTP", c.otp)
	}
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", contentTypeJSONAPI)
	}
	return req, nil
}

// do sends req and returns the raw *http.Response for the caller to
// decode — network/transport-level failures (not HTTP-status failures)
// are returned as an error here.
//
// A 429 is retried transparently while the request is safe to repeat and the
// budget allows. Credential-accepting endpoints run on a tight per-IP budget
// (5 req/s by default) and the calls a licensing client makes on a timer —
// validate, heartbeat ping, check-in — are exactly the ones inside it, so
// without backoff one throttled request becomes a sustained burst that keeps
// the bucket empty and the client never recovers on its own.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	retryable := isRetryable(req.Method, req.URL.Path)

	// Buffer the body once so the request can actually be replayed; an
	// io.Reader is consumed by the first attempt.
	var body []byte
	if req.Body != nil && req.GetBody != nil {
		rc, err := req.GetBody()
		if err == nil {
			body, _ = io.ReadAll(rc)
			_ = rc.Close()
		}
	}

	for attempt := 0; ; attempt++ {
		if attempt > 0 && body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("tamga: request failed: %w", err)
		}

		if resp.StatusCode != http.StatusTooManyRequests || !retryable || attempt >= c.maxRetries {
			return resp, nil
		}

		secs, ok := parseRetryAfter(resp)
		delay := retryDelay(attempt, secs, ok)
		// The response is being discarded, so its body must be drained and
		// closed or the connection cannot be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
		}
	}
}

// retryablePOSTSuffixes are the POST paths safe to repeat after a 429.
//
// They are effectively idempotent (validate, check in/out, ping a heartbeat)
// and they are precisely the calls a client makes on a timer. Creates are
// deliberately absent: retrying POST /machines risks a second activation
// burning a second seat, and only the caller knows whether that is acceptable.
var retryablePOSTSuffixes = []string{
	"/actions/validate",
	"/actions/validate-key",
	"/actions/check-in",
	"/actions/check-out",
	"/actions/ping",
}

func isRetryable(method, path string) bool {
	if method == http.MethodGet {
		return true
	}
	if method != http.MethodPost {
		return false
	}
	for _, suffix := range retryablePOSTSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// parseRetryAfter reads Retry-After as delta-seconds.
//
// The HTTP-date form is ignored deliberately: the server sends seconds, and
// misreading a date as a duration would be far worse than falling back to the
// client's own backoff.
func parseRetryAfter(resp *http.Response) (int, bool) {
	raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if raw == "" {
		return 0, false
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs < 0 {
		return 0, false
	}
	return secs, true
}

// retryDelay is how long to wait before retry number attempt (0-based).
//
// Prefers the server's Retry-After — it knows when the bucket refills, and
// guessing wastes the budget — but caps it, so a misconfigured or hostile
// proxy cannot park the caller for an hour on one header. Otherwise
// exponential backoff with jitter, because a fleet that all retries on the
// same schedule reconverges into the spike it was backing off from.
func retryDelay(attempt int, retryAfter int, hasRetryAfter bool) time.Duration {
	if hasRetryAfter {
		if retryAfter > 60 {
			retryAfter = 60
		}
		return time.Duration(retryAfter) * time.Second
	}
	shift := attempt
	if shift > 5 {
		shift = 5
	}
	base := time.Duration(1<<uint(shift)) * time.Second
	//nolint:gosec // jitter only needs to break synchronization across a
	// retrying fleet, not resist prediction — math/rand is the right tool
	// here, crypto/rand would be paying an unnecessary syscall per retry.
	return base + time.Duration(rand.Int63n(int64(time.Second)))
}

// mapError reads a non-2xx response body as a JSON:API error document and
// returns the corresponding *APIError, populated with the response's
// status and headers. Falls back to a synthetic "UNKNOWN" error (status
// only, no server-provided detail) if the body isn't valid JSON:API error
// JSON — a non-JSON error page (e.g. from a proxy in front of the API)
// must not panic or silently swallow the failure.
//
// mapError takes ownership of closing resp.Body (it must read the full
// body to parse it as JSON, then closes it). Callers must not also close
// resp.Body when they call mapError — only close it themselves on the
// success path they handle separately, or the body gets double-closed.
func mapError(resp *http.Response) error {
	defer func() { _ = resp.Body.Close() }()
	info := ResponseInfoFromHeader(resp.Header)
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return &APIError{
			HTTPStatus: resp.StatusCode,
			Err: Error{
				Code:   "UNKNOWN",
				Title:  "Unknown Error",
				Detail: fmt.Sprintf("server returned %d and the body could not be read: %v", resp.StatusCode, readErr),
			},
			Response: info,
		}
	}
	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil || len(errResp.Errors) == 0 {
		return &APIError{
			HTTPStatus: resp.StatusCode,
			Err: Error{
				Code:   "UNKNOWN",
				Title:  "Unknown Error",
				Detail: fmt.Sprintf("server returned %d with a non-JSON:API body", resp.StatusCode),
			},
			Response: info,
		}
	}
	apiErr := newAPIErrorFromResponse(resp.StatusCode, errResp)
	apiErr.Response = info
	return apiErr
}

// envelope is the generic `{"data": T}` JSON:API response shape.
type envelope[T any] struct {
	Data T `json:"data"`
}

// envelopeWithMeta is the generic `{"data": T, "meta": M}` JSON:API
// response shape used by the validate/offline-proof endpoints.
type envelopeWithMeta[T any, M any] struct {
	Data T `json:"data"`
	Meta M `json:"meta"`
}

// decodeJSONAPI sends a JSON:API request and decodes a `{"data": T}`
// envelope on success, or maps a non-2xx response to an *APIError.
func decodeJSONAPI[T any](ctx context.Context, c *Client, method, path string, body any) (T, error) {
	var zero T
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return zero, err
	}
	resp, err := c.do(req)
	if err != nil {
		return zero, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, mapError(resp)
	}
	defer func() { _ = resp.Body.Close() }()
	var env envelope[T]
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return zero, fmt.Errorf("tamga: decode response body: %w", err)
	}
	return env.Data, nil
}

// decodeJSONAPIWithMeta is decodeJSONAPI's counterpart for endpoints whose
// response carries both `data` and `meta` (the three validate endpoints,
// and generate-offline-proof).
func decodeJSONAPIWithMeta[T any, M any](ctx context.Context, c *Client, method, path string, body any) (T, M, error) {
	var zeroT T
	var zeroM M
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return zeroT, zeroM, err
	}
	resp, err := c.do(req)
	if err != nil {
		return zeroT, zeroM, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zeroT, zeroM, mapError(resp)
	}
	defer func() { _ = resp.Body.Close() }()
	var env envelopeWithMeta[T, M]
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return zeroT, zeroM, fmt.Errorf("tamga: decode response body: %w", err)
	}
	return env.Data, env.Meta, nil
}

// decodeFlat sends a request expecting a flat (non-enveloped) JSON body —
// used only by QuickValidate today, which returns plain application/json
// with no "data" key (docs/sdk.md §1's documented special case).
func decodeFlat[T any](ctx context.Context, c *Client, method, path string) (T, error) {
	var zero T
	req, err := c.newRequest(ctx, method, path, nil)
	if err != nil {
		return zero, err
	}
	resp, err := c.do(req)
	if err != nil {
		return zero, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, mapError(resp)
	}
	defer func() { _ = resp.Body.Close() }()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return zero, fmt.Errorf("tamga: decode response body: %w", err)
	}
	return out, nil
}

// doNoContent sends a request expecting an empty/no-content success body
// (e.g. DELETE /machines/{id}) and returns only the mapped error, if any.
func doNoContent(ctx context.Context, c *Client, method, path string) error {
	req, err := c.newRequest(ctx, method, path, nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	// mapError takes ownership of closing resp.Body on the error path (see
	// its own doc comment) — closing it here unconditionally as well
	// would double-close it. Only close on the success path below,
	// matching decodeJSONAPI/decodeJSONAPIWithMeta/decodeFlat's pattern.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapError(resp)
	}
	_ = resp.Body.Close()
	return nil
}

// doRawText sends a request and returns the raw response body as a
// string — used by the checkout GET endpoints, which return
// application/octet-stream (the PEM-wrapped .lic/.machine text) rather
// than JSON:API.
func doRawText(ctx context.Context, c *Client, method, path string, query url.Values) (string, error) {
	req, err := c.newRequest(ctx, method, path, nil)
	if err != nil {
		return "", err
	}
	if len(query) > 0 {
		req.URL.RawQuery = query.Encode()
	}
	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	// See doNoContent's comment: mapError closes resp.Body itself on the
	// error path, so the defer-close below must only be registered once
	// we know we're on the success path, to avoid a double close.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", mapError(resp)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("tamga: read response body: %w", err)
	}
	return string(body), nil
}
