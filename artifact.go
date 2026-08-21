package tamga

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Artifact is the `artifacts` JSON:API resource — the uploaded binary
// belonging to a release, and the thing an updater actually fetches once
// CheckUpgrade has told it a newer release exists.
//
// Read-only from this SDK. A license key authenticates as the LicenseToken
// role, which holds `artifact.read` and `artifact.download` but not
// `artifact.create`/`update`/`delete` (authz/mod.rs) — publishing an
// artifact is a build-pipeline concern carried out with a product or
// environment token, so this package deliberately wraps only the three
// read/download routes.
type Artifact struct {
	ID         string             `json:"id"`
	Type       string             `json:"type"`
	Attributes ArtifactAttributes `json:"attributes"`
}

// ArtifactAttributes is the attribute bag of an Artifact resource.
//
// ⚠️ Same two-rules-at-once trap as ReleaseAttributes, and it has to be
// read the same way. The server's ArtifactAttributes carries
// rename_all = "camelCase", so redirect_url goes over the wire as
// redirectUrl — but created_at and updated_at each carry an explicit
// per-field rename that overrides the struct rule, so their wire names are
// the bare `created` and `updated`, NOT createdAt/updatedAt
// (artifacts/serializer.rs:20,34-37).
//
// Applying camelCase uniformly here yields two null timestamps; applying
// snake_case uniformly yields a missing redirectUrl. The tags below are
// transcribed from the server's own serializer rather than inferred from a
// rule, and a fixture for this resource must be derived the same way — a
// fixture built from these field names would agree with them and disagree
// with the server.
//
// RedirectURL is populated only by the download action, and only when that
// action was asked for the URL rather than a redirect (see
// ArtifactDownloadURL). The server omits the key entirely on list and show
// rather than sending null, so it decodes to nil on both.
//
// Filesize is a byte count here, unlike MachineAttributes.Memory/Disk which
// are megabytes. The server stores it as a nullable i64 and never derives
// it, so it is whatever the upload reported.
type ArtifactAttributes struct {
	Filetype    *string         `json:"filetype"`
	Filesize    *int64          `json:"filesize"`
	Checksum    *string         `json:"checksum"`
	Platform    *string         `json:"platform"`
	Arch        *string         `json:"arch"`
	Signature   *string         `json:"signature"`
	RedirectURL *string         `json:"redirectUrl"`
	Filename    string          `json:"filename"`
	Status      string          `json:"status"`
	Created     string          `json:"created"`
	Updated     string          `json:"updated"`
	Metadata    json.RawMessage `json:"metadata"`
}

// ArtifactPage is a single page of ListReleaseArtifacts results.
//
// Keyset-paginated with a synthetic cursor, like ComponentPage and
// ProcessPage — not offset-paginated like MachinePage.
type ArtifactPage struct {
	NextCursor *string
	Items      []Artifact
}

// ListReleaseArtifacts lists a release's artifacts, keyset-paginated
// (limit/page[after]).
// GET /v1/accounts/{account_id}/releases/{release_id}/artifacts.
//
// The response carries no cursor metadata and no links, so NextCursor is
// derived: it is set to the last item's ID when a full page came back and
// left nil on a short or empty page. Feed it to the next call as
// ListOptions.After. Sizing matters for that rule to hold, so an unset
// ListOptions.Limit sends an explicit limit of 100 (the server maximum)
// rather than accepting the server's silent 25-row default.
//
// Unlike the download action, this route enforces only the `artifact.read`
// permission — it does not consult the owning release's read gate, so a
// CLOSED release's artifacts are listed here and refused at download.
// Discovering an artifact is therefore not evidence it can be fetched.
func (c *Client) ListReleaseArtifacts(ctx context.Context, releaseID string, opts ListOptions) (*ArtifactPage, error) {
	path := fmt.Sprintf("/releases/%s/artifacts", escapePathSegment(releaseID))
	limit := effectivePageLimit(opts.Limit)
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	if opts.After != nil {
		query.Set("page[after]", *opts.After)
	}
	items, err := decodeJSONAPI[[]Artifact](ctx, c, "GET", path+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	page := &ArtifactPage{Items: items}
	if len(items) == limit {
		last := items[len(items)-1].ID
		page.NextCursor = &last
	}
	return page, nil
}

// GetArtifact fetches one artifact's metadata.
// GET /v1/accounts/{account_id}/artifacts/{artifact_id}.
//
// Metadata only: ArtifactAttributes.RedirectURL is always nil here,
// because the server omits it outside the download action. Use
// ArtifactDownloadURL or DownloadArtifact to get at the bytes.
//
// The checksum returned here is the one to verify a downloaded file
// against — fetch the metadata over the authenticated API, then check the
// credential-free download against it.
func (c *Client) GetArtifact(ctx context.Context, artifactID string) (*Artifact, error) {
	artifact, err := decodeJSONAPI[Artifact](ctx, c, "GET", fmt.Sprintf("/artifacts/%s", escapePathSegment(artifactID)), nil)
	if err != nil {
		return nil, err
	}
	return &artifact, nil
}

// ArtifactDownloadTTLMin and ArtifactDownloadTTLMax bound
// DownloadArtifactOptions.TTL. The server validates the same range
// (artifacts/service.rs — PRESIGN_TTL_MIN/PRESIGN_TTL_MAX) and answers a
// 422 outside it; this package refuses locally first so the failure names
// the field instead of arriving as a server error.
const (
	ArtifactDownloadTTLMin = 60 * time.Second
	ArtifactDownloadTTLMax = 7 * 24 * time.Hour
)

// DownloadArtifactOptions configures ArtifactDownloadURL and
// DownloadArtifact. The zero value is valid and lets the server choose the
// presigned URL's lifetime.
type DownloadArtifactOptions struct {
	// TTL is how long the presigned storage URL stays valid. Zero means
	// "let the server decide". The wire parameter counts whole seconds, so
	// a sub-second TTL would truncate to 0 and be refused by the server as
	// out of range — validate rejects it locally instead, naming the field.
	TTL time.Duration
}

// query renders the options as the wire query string.
//
// redirect=false is not optional and is not a caller choice: it is what
// keeps the license key away from the storage host. See
// ArtifactDownloadURL.
func (o DownloadArtifactOptions) query() (url.Values, error) {
	q := url.Values{}
	q.Set("redirect", "false")
	if o.TTL != 0 {
		secs := int64(o.TTL / time.Second)
		if o.TTL < ArtifactDownloadTTLMin || time.Duration(secs)*time.Second > ArtifactDownloadTTLMax {
			return nil, fmt.Errorf("tamga: DownloadArtifactOptions.TTL must be between %v and %v, got %v", ArtifactDownloadTTLMin, ArtifactDownloadTTLMax, o.TTL)
		}
		q.Set("ttl", strconv.FormatInt(secs, 10))
	}
	return q, nil
}

// ArtifactDownloadURL asks the server for a short-lived presigned storage
// URL for an artifact's bytes, without following the redirect to it.
// GET /v1/accounts/{account_id}/artifacts/{artifact_id}/actions/download.
//
// ⚠️ The reason this method exists rather than a plain "GET the download
// action" is a credential leak. By default that route answers 303 See
// Other pointing at the storage host, and an HTTP client that follows the
// redirect can carry the request's Authorization header — the raw license
// key — to a host that is not the Tamga API. Go's standard library drops
// Authorization only when the redirect leaves the original domain, and
// still forwards it to a subdomain; every other header, Tamga-OTP
// included, is forwarded unconditionally. So this method sends
// ?redirect=false, which makes the server return the artifact resource
// with redirectUrl populated, AND sends it through a redirect-suppressing
// copy of the configured HTTP client, so a server or proxy that answers a
// redirect anyway cannot cause one to be followed. In that case the URL is
// taken from the Location header instead, which is the same URL and still
// reached without a second authenticated request.
//
// Fetch the returned URL with NO credentials — DownloadArtifact does
// exactly that. A presigned URL carries its own authorization in its query
// string, and S3-compatible storage commonly rejects a request that also
// carries an Authorization header.
//
// A 403 here is not necessarily an auth misconfiguration. The handler
// enforces the owning release's read gate (enforce_release_access) as well
// as the `artifact.download` permission, so a CLOSED release's binary is
// refused even to a caller that holds the permission — and the same
// artifact is still visible through ListReleaseArtifacts and GetArtifact,
// which do not apply that gate. Check the release's status before
// concluding the token is wrong.
//
// A 422 STORAGE_UNAVAILABLE means the server has no storage backend
// configured at all, which no client action resolves.
func (c *Client) ArtifactDownloadURL(ctx context.Context, artifactID string, opts DownloadArtifactOptions) (string, error) {
	query, err := opts.query()
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("/artifacts/%s/actions/download?%s", escapePathSegment(artifactID), query.Encode())
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.doWith(c.noRedirectClient(), req)
	if err != nil {
		return "", err
	}
	// A redirect reached this point only because redirect-following is
	// suppressed, so nothing was sent to the storage host. Location is the
	// presigned URL the 303 would have gone to.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if location == "" {
			return "", fmt.Errorf("tamga: download action answered %d with no Location header", resp.StatusCode)
		}
		return location, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", mapError(resp)
	}
	defer func() { _ = resp.Body.Close() }()
	var env envelope[Artifact]
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "", fmt.Errorf("tamga: decode response body: %w", err)
	}
	if env.Data.Attributes.RedirectURL == nil || *env.Data.Attributes.RedirectURL == "" {
		return "", fmt.Errorf("tamga: download action returned no redirectUrl")
	}
	return *env.Data.Attributes.RedirectURL, nil
}

// DownloadArtifact resolves the presigned URL with ArtifactDownloadURL and
// then fetches the bytes from storage with NO credentials attached — no
// Authorization header, no Tamga-Version, no Tamga-OTP, no User-Agent from
// this package. The caller owns the returned stream and must Close it.
//
// Verify what comes back. Nothing in this path authenticates the bytes:
// pair it with GetArtifact and check the stream against
// ArtifactAttributes.Checksum (and Signature, where the product publishes
// one) before executing or installing anything.
//
// The storage fetch reuses the *http.Client this Client was built with, so
// proxy, TLS and timeout configuration still apply. If that client was
// supplied via WithHTTPClient and its Transport injects credentials of its
// own, those credentials WILL reach the storage host — this package can
// only guarantee it does not send its own. Use ArtifactDownloadURL and
// fetch it yourself in that case.
//
// Only http and https URLs are followed. The URL is chosen by the server,
// and a custom Transport may have other schemes registered
// (http.Transport.RegisterProtocol), so the scheme is checked rather than
// assumed.
func (c *Client) DownloadArtifact(ctx context.Context, artifactID string, opts DownloadArtifactOptions) (io.ReadCloser, error) {
	rawURL, err := c.ArtifactDownloadURL(ctx, artifactID, opts)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tamga: parse artifact download URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("tamga: refusing to fetch artifact from a %q URL", parsed.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("tamga: build request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tamga: request failed: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Storage answers its own error format, not JSON:API, so mapError
		// would only ever produce a synthetic UNKNOWN here. Report the
		// status plainly and say where it came from — a presigned URL that
		// has expired is the common case and it is not a Tamga error.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("tamga: artifact storage returned %d (the presigned URL may have expired)", resp.StatusCode)
	}
	return resp.Body, nil
}
