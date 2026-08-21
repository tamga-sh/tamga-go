package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// artifactJSON is the server's own wire shape, transcribed from
// artifacts/serializer.rs rather than from this package's struct tags. Note
// redirectUrl (camelCase, per rename_all) sitting next to created/updated
// (bare, per the explicit per-field renames that override it) — a fixture
// derived from the Go struct would agree with the Go struct and disagree
// with the server, which is the exact failure this shape exists to catch.
func artifactJSON(id, filename string, withRedirect bool) string {
	redirect := ""
	if withRedirect {
		redirect = `"redirectUrl":"https://storage.example.test/blob?sig=abc",`
	}
	return fmt.Sprintf(`{
		"id":%q,"type":"artifacts",
		"attributes":{
			"filename":%q,"filetype":"dmg","filesize":1048576,
			"checksum":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"platform":"darwin","arch":"arm64","signature":null,"status":"UPLOADED",
			%s"metadata":{"channel":"stable"},
			"created":"2026-01-01T00:00:00Z","updated":"2026-01-02T00:00:00Z"
		}
	}`, id, filename, redirect)
}

func TestListReleaseArtifacts_KeysetQueryAndDerivedCursor(t *testing.T) {
	var gotPath string
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + artifactJSON("a1", "app.dmg", false) + `,` + artifactJSON("a2", "app.zip", false) + `]}`))
	})
	defer closeFn()

	page, err := c.ListReleaseArtifacts(context.Background(), "rel-1", ListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListReleaseArtifacts() error = %v", err)
	}
	if gotPath != "/v1/accounts/acct-123/releases/rel-1/artifacts" {
		t.Errorf("path = %s", gotPath)
	}
	if got := gotQuery.Get("limit"); got != "2" {
		t.Errorf("limit = %q", got)
	}
	for _, offsetParam := range []string{"page[size]", "page[number]"} {
		if _, ok := gotQuery[offsetParam]; ok {
			t.Errorf("%s was sent to a keyset route", offsetParam)
		}
	}
	if page.NextCursor == nil || *page.NextCursor != "a2" {
		t.Errorf("NextCursor = %v, want the last item's id on a full page", page.NextCursor)
	}
}

func TestListReleaseArtifacts_UnsetLimitSendsTheServerMaximum(t *testing.T) {
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[` + artifactJSON("a1", "app.dmg", false) + `]}`))
	})
	defer closeFn()

	page, err := c.ListReleaseArtifacts(context.Background(), "rel-1", ListOptions{})
	if err != nil {
		t.Fatalf("ListReleaseArtifacts() error = %v", err)
	}
	// An unset limit must not accept the server's silent 25-row default,
	// or the derived cursor rule ("a full page means there may be more")
	// is computed against a page size the caller never chose.
	if got := gotQuery.Get("limit"); got != "100" {
		t.Errorf("limit = %q, want 100", got)
	}
	if page.NextCursor != nil {
		t.Errorf("NextCursor = %v, want nil on a short page", *page.NextCursor)
	}
}

func TestListReleaseArtifacts_AfterCursorIsSent(t *testing.T) {
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	defer closeFn()

	after := "a1"
	if _, err := c.ListReleaseArtifacts(context.Background(), "rel-1", ListOptions{After: &after}); err != nil {
		t.Fatalf("ListReleaseArtifacts() error = %v", err)
	}
	if got := gotQuery.Get("page[after]"); got != "a1" {
		t.Errorf("page[after] = %q", got)
	}
}

// TestArtifactAttributes_TimestampsAreBareNotCamelCased is the trap test.
// ArtifactAttributes carries rename_all = "camelCase" AND explicit
// #[serde(rename = "created")]/#[serde(rename = "updated")] on the two
// timestamps, so a port that applies camelCase uniformly gets two empty
// strings while everything else decodes fine.
func TestArtifactAttributes_TimestampsAreBareNotCamelCased(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + artifactJSON("a1", "app.dmg", false) + `}`))
	})
	defer closeFn()

	artifact, err := c.GetArtifact(context.Background(), "a1")
	if err != nil {
		t.Fatalf("GetArtifact() error = %v", err)
	}
	if artifact.Attributes.Created != "2026-01-01T00:00:00Z" {
		t.Errorf("Created = %q, want the bare `created` key to decode", artifact.Attributes.Created)
	}
	if artifact.Attributes.Updated != "2026-01-02T00:00:00Z" {
		t.Errorf("Updated = %q, want the bare `updated` key to decode", artifact.Attributes.Updated)
	}

	// The other half of the same trap: a body that camelCases the
	// timestamps — which is what a uniformly-camelCased port would both
	// emit and expect — must NOT populate them. If it does, the tags were
	// written to accept both spellings and the wire contract is no longer
	// pinned by this test.
	var camelCased Artifact
	body := []byte(`{"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z","filename":"app.dmg"}`)
	if err := json.Unmarshal(body, &camelCased.Attributes); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if camelCased.Attributes.Created != "" || camelCased.Attributes.Updated != "" {
		t.Errorf("createdAt/updatedAt populated Created/Updated (%q/%q); the wire names are `created`/`updated`",
			camelCased.Attributes.Created, camelCased.Attributes.Updated)
	}
	if camelCased.Attributes.Filename != "app.dmg" {
		t.Error("the control field did not decode, so the assertion above proves nothing")
	}
}

// TestArtifactAttributes_RedirectURLIsCamelCased is the other half of the
// same struct rule: redirect_url DOES follow rename_all, so its wire name
// is redirectUrl. Getting the timestamps right by applying snake_case
// uniformly would break this one.
func TestArtifactAttributes_RedirectURLIsCamelCased(t *testing.T) {
	var raw Artifact
	body := []byte(`{"redirectUrl":"https://storage.example.test/blob","filename":"app.dmg"}`)
	if err := json.Unmarshal(body, &raw.Attributes); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if raw.Attributes.RedirectURL == nil || *raw.Attributes.RedirectURL != "https://storage.example.test/blob" {
		t.Errorf("RedirectURL = %v, want the camelCased redirectUrl key to decode", raw.Attributes.RedirectURL)
	}

	var snake Artifact
	if err := json.Unmarshal([]byte(`{"redirect_url":"https://storage.example.test/blob"}`), &snake.Attributes); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snake.Attributes.RedirectURL != nil {
		t.Errorf("redirect_url populated RedirectURL; the wire name is redirectUrl")
	}
}

func TestGetArtifact_PathAndNilRedirectURL(t *testing.T) {
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + artifactJSON("a1", "app.dmg", false) + `}`))
	})
	defer closeFn()

	artifact, err := c.GetArtifact(context.Background(), "a1")
	if err != nil {
		t.Fatalf("GetArtifact() error = %v", err)
	}
	if gotPath != "/v1/accounts/acct-123/artifacts/a1" {
		t.Errorf("path = %s", gotPath)
	}
	// The server omits the key entirely outside the download action.
	if artifact.Attributes.RedirectURL != nil {
		t.Errorf("RedirectURL = %v, want nil on a show response", *artifact.Attributes.RedirectURL)
	}
	if artifact.Attributes.Filesize == nil || *artifact.Attributes.Filesize != 1048576 {
		t.Errorf("Filesize = %v", artifact.Attributes.Filesize)
	}
	if artifact.Attributes.Signature != nil {
		t.Errorf("Signature = %v, want nil for an explicit null", *artifact.Attributes.Signature)
	}
}

func TestArtifactDownloadURL_SendsRedirectFalseAndTTL(t *testing.T) {
	var gotPath string
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + artifactJSON("a1", "app.dmg", true) + `}`))
	})
	defer closeFn()

	got, err := c.ArtifactDownloadURL(context.Background(), "a1", DownloadArtifactOptions{TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("ArtifactDownloadURL() error = %v", err)
	}
	if gotPath != "/v1/accounts/acct-123/artifacts/a1/actions/download" {
		t.Errorf("path = %s", gotPath)
	}
	// redirect=false is what keeps the license key off the storage host;
	// it is not a caller option and must be sent unconditionally.
	if redirect := gotQuery.Get("redirect"); redirect != "false" {
		t.Errorf("redirect = %q, want false", redirect)
	}
	// The wire parameter counts whole seconds, not the Duration's nanos.
	if ttl := gotQuery.Get("ttl"); ttl != "300" {
		t.Errorf("ttl = %q, want 300", ttl)
	}
	if got != "https://storage.example.test/blob?sig=abc" {
		t.Errorf("url = %q", got)
	}
}

func TestArtifactDownloadURL_ZeroTTLSendsNoTTLParam(t *testing.T) {
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + artifactJSON("a1", "app.dmg", true) + `}`))
	})
	defer closeFn()

	if _, err := c.ArtifactDownloadURL(context.Background(), "a1", DownloadArtifactOptions{}); err != nil {
		t.Fatalf("ArtifactDownloadURL() error = %v", err)
	}
	if _, ok := gotQuery["ttl"]; ok {
		t.Errorf("ttl = %q was sent for the zero value; the server should choose", gotQuery.Get("ttl"))
	}
	if got := gotQuery.Get("redirect"); got != "false" {
		t.Errorf("redirect = %q, want false even with no TTL", got)
	}
}

func TestArtifactDownloadURL_TTLOutOfRangeIsRefusedLocally(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
	}{
		{"below the minute floor", 30 * time.Second},
		{"sub-second, which would truncate to zero on the wire", 500 * time.Millisecond},
		{"negative", -time.Hour},
		{"beyond a week", 8 * 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hits int
			c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				hits++
				w.Header().Set("Content-Type", "application/vnd.api+json")
				_, _ = w.Write([]byte(`{"data":` + artifactJSON("a1", "app.dmg", true) + `}`))
			})
			defer closeFn()

			_, err := c.ArtifactDownloadURL(context.Background(), "a1", DownloadArtifactOptions{TTL: tt.ttl})
			if err == nil {
				t.Fatalf("ArtifactDownloadURL(TTL=%v) = no error, want a local refusal", tt.ttl)
			}
			if !strings.Contains(err.Error(), "TTL") {
				t.Errorf("error = %q, want it to name the field", err.Error())
			}
			if hits != 0 {
				t.Errorf("the request was sent anyway (%d hits); an out-of-range TTL is refused before the network", hits)
			}
		})
	}
}

func TestArtifactDownloadURL_TTLBoundsAreInclusive(t *testing.T) {
	for _, ttl := range []time.Duration{ArtifactDownloadTTLMin, ArtifactDownloadTTLMax} {
		var gotQuery url.Values
		c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.Query()
			w.Header().Set("Content-Type", "application/vnd.api+json")
			_, _ = w.Write([]byte(`{"data":` + artifactJSON("a1", "app.dmg", true) + `}`))
		})
		if _, err := c.ArtifactDownloadURL(context.Background(), "a1", DownloadArtifactOptions{TTL: ttl}); err != nil {
			t.Errorf("ArtifactDownloadURL(TTL=%v) error = %v, want the boundary accepted", ttl, err)
		}
		if gotQuery.Get("ttl") == "" {
			t.Errorf("ttl was not sent for %v", ttl)
		}
		closeFn()
	}
}

// TestArtifactDownloadURL_NeverFollowsThe303ToStorage is the credential
// test, and it is the reason this method exists rather than a plain GET.
//
// Both httptest servers listen on 127.0.0.1, differing only by port — and
// Go's net/http strips Authorization on a redirect only when the redirect
// leaves the original *host*, port not considered. So a client that follows
// this 303 hands the raw license key to the storage server, which is
// exactly the real-world shape of storage running on the same host or on a
// subdomain of the API. Nothing must reach the storage server at all here.
func TestArtifactDownloadURL_NeverFollowsThe303ToStorage(t *testing.T) {
	var storageHits int
	var storageAuth string
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storageHits++
		storageAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("BINARY"))
	}))
	defer storage.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, storage.URL+"/blob?sig=abc", http.StatusSeeOther)
	}))
	defer api.Close()

	c, err := New("acct-123", WithBaseURL(api.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := c.ArtifactDownloadURL(context.Background(), "a1", DownloadArtifactOptions{})
	if err != nil {
		t.Fatalf("ArtifactDownloadURL() error = %v", err)
	}
	if storageHits != 0 {
		t.Errorf("the redirect was followed: storage received %d request(s) carrying Authorization %q", storageHits, storageAuth)
	}
	// The Location header is the same presigned URL the 303 pointed at, so
	// suppressing the redirect costs nothing.
	if want := storage.URL + "/blob?sig=abc"; got != want {
		t.Errorf("url = %q, want the Location header %q", got, want)
	}
}

func TestArtifactDownloadURL_RedirectWithNoLocationIsAnError(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSeeOther)
	})
	defer closeFn()

	if _, err := c.ArtifactDownloadURL(context.Background(), "a1", DownloadArtifactOptions{}); err == nil {
		t.Fatal("expected an error for a 303 with no Location header")
	}
}

func TestArtifactDownloadURL_MissingRedirectURLIsAnError(t *testing.T) {
	for _, body := range []string{
		`{"data":` + artifactJSON("a1", "app.dmg", false) + `}`,
		`{"data":{"id":"a1","type":"artifacts","attributes":{"filename":"app.dmg","redirectUrl":""}}}`,
	} {
		c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/vnd.api+json")
			_, _ = w.Write([]byte(body))
		})
		if _, err := c.ArtifactDownloadURL(context.Background(), "a1", DownloadArtifactOptions{}); err == nil {
			t.Errorf("expected an error when the download action returned no redirectUrl")
		}
		closeFn()
	}
}

// TestArtifactDownloadURL_ForbiddenSurfacesAsAPIError covers the release
// read gate. enforce_release_access runs on this route in addition to the
// permission check, so a CLOSED release's binary is refused to a caller
// that genuinely holds artifact.download — the 403 must arrive as an
// ordinary *APIError the caller can inspect, not be swallowed.
func TestArtifactDownloadURL_ForbiddenSurfacesAsAPIError(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"code":"FORBIDDEN","title":"Forbidden","detail":"release is not accessible"}]}`))
	})
	defer closeFn()

	_, err := c.ArtifactDownloadURL(context.Background(), "a1", DownloadArtifactOptions{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want an *APIError", err)
	}
	if apiErr.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want 403", apiErr.HTTPStatus)
	}
}

// TestDownloadArtifact_FetchesStorageWithNoCredentials is the second half
// of the leak guard: having refused to let the redirect carry the license
// key, the explicit fetch must not send it either — nor any other header
// this package attaches to an API request.
func TestDownloadArtifact_FetchesStorageWithNoCredentials(t *testing.T) {
	var storageHits int
	var storageHeaders http.Header
	var storageQuery url.Values
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storageHits++
		storageHeaders = r.Header.Clone()
		storageQuery = r.URL.Query()
		_, _ = w.Write([]byte("BINARY-PAYLOAD"))
	}))
	defer storage.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = fmt.Fprintf(w, `{"data":{"id":"a1","type":"artifacts","attributes":{"filename":"app.dmg","status":"UPLOADED","metadata":{},"redirectUrl":%q,"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`, storage.URL+"/blob?sig=abc")
	}))
	defer api.Close()

	c, err := New("acct-123", WithBaseURL(api.URL), WithLicenseKey("lic-abc"), WithOTP("123456"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	body, err := c.DownloadArtifact(context.Background(), "a1", DownloadArtifactOptions{})
	if err != nil {
		t.Fatalf("DownloadArtifact() error = %v", err)
	}
	defer func() { _ = body.Close() }()
	payload, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(payload) != "BINARY-PAYLOAD" {
		t.Errorf("body = %q", payload)
	}
	if storageHits != 1 {
		t.Fatalf("storage hits = %d, want exactly 1", storageHits)
	}
	for _, header := range []string{"Authorization", "Tamga-Version", "Tamga-OTP", "Cookie"} {
		if got := storageHeaders.Get(header); got != "" {
			t.Errorf("storage received %s: %q — no credential or Tamga header may leave the API host", header, got)
		}
	}
	// The presigned URL's own query string carries its authorization and
	// must survive intact.
	if got := storageQuery.Get("sig"); got != "abc" {
		t.Errorf("sig = %q, want the presigned query preserved", got)
	}
}

// recordingRoundTripper answers every request with 200 and records that it
// was reached, standing in for a scheme a caller registered on their own
// Transport (http.Transport.RegisterProtocol).
type recordingRoundTripper struct{ hits int }

func (rt *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.hits++
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("PWNED")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestDownloadArtifact_RefusesANonHTTPScheme checks the scheme, not just
// that something failed. The redirectUrl is chosen by the server, and a
// caller's Transport may have other schemes registered — so the test
// registers one that would happily succeed, and asserts it is never
// reached. Relying on Go's own "unsupported protocol scheme" error would
// prove nothing here: it fires for the wrong reason and disappears the
// moment a caller registers the scheme, which is exactly the case the
// check exists for.
func TestDownloadArtifact_RefusesANonHTTPScheme(t *testing.T) {
	evil := &recordingRoundTripper{}
	transport := &http.Transport{}
	transport.RegisterProtocol("evil", evil)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"a1","type":"artifacts","attributes":{"filename":"app.dmg","redirectUrl":"evil://storage/blob"}}}`))
	}))
	defer api.Close()

	c, err := New("acct-123", WithBaseURL(api.URL), WithLicenseKey("lic-abc"),
		WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	body, err := c.DownloadArtifact(context.Background(), "a1", DownloadArtifactOptions{})
	if err == nil {
		_ = body.Close()
		t.Fatal("expected a refusal for a non-http(s) URL")
	}
	if evil.hits != 0 {
		t.Errorf("the %q URL was fetched anyway (%d hits)", "evil", evil.hits)
	}
	if !strings.Contains(err.Error(), "refusing to fetch") || !strings.Contains(err.Error(), "evil") {
		t.Errorf("error = %q, want this package's own refusal naming the scheme", err.Error())
	}
}

func TestDownloadArtifact_StorageErrorIsReportedPlainly(t *testing.T) {
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>`))
	}))
	defer storage.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = fmt.Fprintf(w, `{"data":{"id":"a1","type":"artifacts","attributes":{"filename":"app.dmg","redirectUrl":%q}}}`, storage.URL+"/blob")
	}))
	defer api.Close()

	c, err := New("acct-123", WithBaseURL(api.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.DownloadArtifact(context.Background(), "a1", DownloadArtifactOptions{})
	if err == nil {
		t.Fatal("expected an error from the storage host")
	}
	// Storage answers its own error format, so an *APIError would be a
	// synthetic UNKNOWN that misattributes the failure to the Tamga API.
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Errorf("storage failure surfaced as *APIError %v; it is not a Tamga API error", apiErr)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want it to report the storage status", err.Error())
	}
}

func TestDownloadArtifact_PropagatesTheURLError(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"NOT_FOUND","title":"Not Found"}]}`))
	})
	defer closeFn()

	if _, err := c.DownloadArtifact(context.Background(), "a1", DownloadArtifactOptions{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound propagated from the URL step", err)
	}
}

func TestArtifactIDsArePathEscaped(t *testing.T) {
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + artifactJSON("a1", "app.dmg", false) + `}`))
	})
	defer closeFn()

	if _, err := c.GetArtifact(context.Background(), "a1/../../other"); err != nil {
		t.Fatalf("GetArtifact() error = %v", err)
	}
	if strings.Contains(gotPath, "/../") {
		t.Errorf("path = %q, want the id escaped rather than traversing", gotPath)
	}
}
