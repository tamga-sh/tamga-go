package tamga

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Release is the `releases` JSON:API resource returned by CheckUpgrade.
type Release struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Attributes ReleaseAttributes `json:"attributes"`
}

// ReleaseAttributes is the attribute bag of a Release resource.
//
// ⚠️ This is one of the few resources the server serializes in camelCase,
// and it is not uniformly camelCase either. ReleaseAttributes carries
// rename_all = "camelCase", so product_id goes over the wire as
// productId — but created_at and updated_at each carry an explicit
// per-field rename that overrides the struct rule, so their wire names
// are the bare `created` and `updated`, NOT createdAt/updatedAt.
//
// Both halves of that have to be right at once. Applying camelCase
// uniformly here yields two null timestamps; applying snake_case
// uniformly yields a missing productId. The tags below are transcribed
// from the server's own serializer rather than inferred from a rule, and
// a fixture for this resource must be derived the same way — a fixture
// built from these field names would agree with them and disagree with
// the server.
//
// Everything an embedded client touches more often — machines, policies,
// licenses, components, processes, entitlements — is plain snake_case.
// Do not generalize either way; read the struct.
//
// Tag is omitted entirely by the server when null rather than sent as
// null, so it decodes to nil in both cases.
type ReleaseAttributes struct {
	Name      *string         `json:"name"`
	Tag       *string         `json:"tag"`
	ProductID string          `json:"productId"`
	Version   string          `json:"version"`
	Channel   string          `json:"channel"`
	Status    string          `json:"status"`
	Created   string          `json:"created"`
	Updated   string          `json:"updated"`
	Metadata  json.RawMessage `json:"metadata"`
}

// UpgradeOptions configures CheckUpgrade.
//
// The first four fields are all REQUIRED by the server — its query
// extractor declares them as bare values rather than Options, so omitting
// any one is a plain-text 400 rather than a JSON:API error document, and
// this SDK refuses the call locally instead of sending it.
type UpgradeOptions struct {
	// ProductID is the product's UUID, not its code or key.
	ProductID string
	// Platform is the release platform key (the same value a
	// release-platforms resource carries as `key`).
	Platform string
	// Filetype is the release filetype key — one word, e.g. "dmg",
	// "exe", "tar.gz" as the server names it. It is NOT a filename.
	Filetype string
	// Version is the caller's currently-installed version, the baseline
	// the server compares candidate releases against.
	Version string
	// Channel optionally restricts the search to one release channel.
	// Omitting it matches EVERY channel, alpha and dev included — pass
	// "stable" (or whatever the product's channels are named) unless
	// pre-release builds really are wanted.
	Channel string
	// Constraint optionally bounds how far the version may move, in the
	// server's own constraint syntax. Omitting it defaults to
	// patch-only.
	Constraint string
}

// validate refuses a call the server would answer with a plain-text 400.
func (o UpgradeOptions) validate() error {
	for _, required := range []struct {
		name  string
		value string
	}{
		{"ProductID", o.ProductID},
		{"Platform", o.Platform},
		{"Filetype", o.Filetype},
		{"Version", o.Version},
	} {
		if required.value == "" {
			return fmt.Errorf("tamga: UpgradeOptions.%s is required by the upgrade check", required.name)
		}
	}
	return nil
}

// query renders the options as the wire query string.
func (o UpgradeOptions) query() url.Values {
	q := url.Values{}
	q.Set("product", o.ProductID)
	q.Set("platform", o.Platform)
	q.Set("filetype", o.Filetype)
	q.Set("version", o.Version)
	if o.Channel != "" {
		q.Set("channel", o.Channel)
	}
	if o.Constraint != "" {
		q.Set("constraint", o.Constraint)
	}
	return q
}

// CheckUpgrade asks whether a newer release is available to this caller.
// GET /v1/accounts/{account_id}/releases/actions/upgrade.
//
// Returns (release, true, nil) when the server offers one, and
// (nil, false, nil) when it answers 204 No Content.
//
// ⚠️ offered == false does NOT mean "you are up to date." The 204 is
// deliberately ambiguous and covers two different situations that the
// server refuses to distinguish:
//
//   - There is no newer release matching the query.
//   - There IS a newer release, but this license is not entitled to move
//     to it — an expired license under an expiration strategy that stops
//     new builds at expiry.
//
// The server's own comment explains the choice: answering "a newer
// version exists but you cannot have it" leaks the existence of a release
// to a caller that may not have it, so it returns the same answer an
// already-current caller gets. Report it to a user as "no update is
// available to you", never as "you are on the latest version", and never
// treat it as evidence the license is healthy.
//
// The other outcomes are ordinary *APIErrors:
//
//   - 403 FORBIDDEN — the license is SUSPENDED. This is checked before
//     the entitlement branch above, so a suspended license never reaches
//     the 204 path at all; it is the one refusal here that is explicit.
//   - 404 NOT_FOUND — the product UUID does not resolve.
//   - 401/403 — the product's distribution strategy refused the caller.
//     A Licensed product needs a bearer carrying release.read; a Closed
//     product admits only admin, developer and product-token roles, so a
//     license key gets 403 there unconditionally.
//   - 400 — a malformed or incomplete query. The server answers that one
//     in plain text rather than JSON:API, so it surfaces as a synthetic
//     UNKNOWN code; the four required fields are checked locally first to
//     keep that from being the usual case.
//
// The route takes optional auth so an Open product's updater keeps
// working with no credential, but this SDK sends its configured transport
// here as it does everywhere else — that keeps the call correct on
// Licensed products too, and forward-compatible if a product's strategy
// is tightened later.
func (c *Client) CheckUpgrade(ctx context.Context, opts UpgradeOptions) (*Release, bool, error) {
	if err := opts.validate(); err != nil {
		return nil, false, err
	}
	req, err := c.newRequest(ctx, "GET", "/releases/actions/upgrade?"+opts.query().Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, false, err
	}
	// mapError takes ownership of closing resp.Body on the error path —
	// see doNoContent — so the success-path close is registered only
	// after the status check.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false, mapError(resp)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		return nil, false, nil
	}
	var env envelope[Release]
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, false, fmt.Errorf("tamga: decode response body: %w", err)
	}
	return &env.Data, true, nil
}
