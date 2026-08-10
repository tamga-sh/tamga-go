package tamga

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

// buildURL joins the configured base URL, the required
// /v1/accounts/{account_id} prefix, and path into a full request URL.
// account_id is path-escaped since it may be either a UUID or an
// account-code-style string (docs/sdk.md §1 — both forms are valid and
// this segment is always present regardless of which form is used).
func (c *Client) buildURL(path string) string {
	return c.baseURL + "/v1/accounts/" + url.PathEscape(c.accountID) + path
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
func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tamga: request failed: %w", err)
	}
	return resp, nil
}

// mapError reads a non-2xx response body as a JSON:API error document and
// returns the corresponding *APIError, populated with the response's
// status and headers. Falls back to a synthetic "UNKNOWN" error (status
// only, no server-provided detail) if the body isn't valid JSON:API error
// JSON — a non-JSON error page (e.g. from a proxy in front of the API)
// must not panic or silently swallow the failure.
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapError(resp)
	}
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", mapError(resp)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("tamga: read response body: %w", err)
	}
	return string(body), nil
}
