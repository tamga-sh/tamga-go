package tamga

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Health is the /v1/health liveness response.
//
// ⚠️ It is NOT a JSON:API resource. The handler returns a flat
// application/json body — {"status","version","uptime_secs"} with no
// data envelope, no type, no id and no attributes bag — so it does not go
// through this package's envelope decoder. Do not model it as one.
//
// Version is the server's own build version, unrelated to the
// Tamga-Version API version this SDK negotiates. UptimeSecs is seconds
// since the process started, and is a u64 server-side: it never goes
// negative.
type Health struct {
	Status     string `json:"status"`
	Version    string `json:"version"`
	UptimeSecs int64  `json:"uptime_secs"`
}

// Health probes the server's liveness endpoint. GET {base}/v1/health.
//
// Two things make this method unlike every other one in this package, and
// both are deliberate.
//
// # It is sent with no credential
//
// This is the single exception to "the configured transport is applied to
// every request". The route is on the server's public list, but
// require_authentication resolves the request's bearer BEFORE it consults
// that list, and propagates a resolution error either way. So a license
// key that is suspended, expired, or refused by its policy's
// authentication_strategy turns the one call whose whole purpose is to
// isolate a transport problem from a credential problem into a 401 about
// the credential.
//
// Whether that bites depends on the server's mode, and the dangerous mode
// is the default. In multiplayer the account id comes from the path,
// /v1/health has no account segment, and resolution short-circuits before
// any lookup — a credential is harmlessly ignored. In singleplayer, which
// is the server's default, the account id comes from configuration and is
// present on every path, so the lookup really runs and a license key
// under a default policy (authentication_strategy = TOKEN) returns 401
// LICENSE_NOT_ALLOWED. Sending anonymously is correct in both modes and
// load-bearing in the default one.
//
// # It does not carry the account prefix
//
// Every other path this package builds is relative to
// /v1/accounts/{account_id}. This one is not, so it is built from the
// configured base URL directly.
//
// # What it is for
//
// It separates a transport-layer problem from a credential one, and there
// is one diagnosis it makes cheap: if every ordinary call is failing with
// 403 "The Host header does not match any configured host" but Health
// succeeds, the fault is the server's TAMGA_ALLOWED_HOSTS configuration
// and not the caller's token. The host-authorization middleware exempts
// /v1/health and /health specifically so a probe keeps working while that
// is misconfigured.
//
// A 429 is still retried by the transport, as on any GET.
func (c *Client) Health(ctx context.Context) (*Health, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/health", nil)
	if err != nil {
		return nil, fmt.Errorf("tamga: build request: %w", err)
	}
	// No Authorization/Cookie/?token and no Tamga-OTP: see above. The two
	// headers below carry no credential and keep the call identifiable in
	// a server log.
	req.Header.Set("Tamga-Version", sanitizeVersion(c.apiVersion))
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	// mapError takes ownership of closing resp.Body on the error path —
	// see doNoContent — so the success-path close is registered only
	// after the status check.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, mapError(resp)
	}
	defer func() { _ = resp.Body.Close() }()
	var health Health
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("tamga: decode response body: %w", err)
	}
	return &health, nil
}
