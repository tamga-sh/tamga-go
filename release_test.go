package tamga

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// serverReleaseJSON is transcribed field-by-field from the server's
// ReleaseResource/ReleaseAttributes serializer, NOT from this package's
// ReleaseAttributes struct tags.
//
// _provenance: tamga-api src/features/releases/serializer.rs.
// ReleaseAttributes carries #[serde(rename_all = "camelCase")], so
// product_id serializes as "productId". Its created_at/updated_at fields
// each carry an explicit #[serde(rename = "created"/"updated")], and a
// per-field rename overrides rename_all, so those two are bare — not
// "createdAt"/"updatedAt". `tag` is #[serde(skip_serializing_if =
// "Option::is_none")] and is therefore absent here rather than null.
//
// Deriving this from the SDK's own field names instead would produce a
// fixture that agrees with the parser and disagrees with the server,
// which is exactly how the fleet shipped a broken release decoder once
// already.
const serverReleaseJSON = `{
	"id":"rel-1","type":"releases",
	"attributes":{
		"productId":"prod-uuid","name":"2.0.0","version":"2.0.0","channel":"stable",
		"status":"PUBLISHED","metadata":{},
		"created":"2026-01-01T00:00:00Z","updated":"2026-01-02T00:00:00Z"
	}
}`

func TestCheckUpgrade_SendsEveryRequiredQueryParam(t *testing.T) {
	var gotPath string
	var gotQuery url.Values
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.Query()
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + serverReleaseJSON + `}`))
	})
	defer closeFn()

	release, offered, err := c.CheckUpgrade(context.Background(), UpgradeOptions{
		ProductID:  "prod-uuid",
		Platform:   "darwin",
		Filetype:   "dmg",
		Version:    "1.9.0",
		Channel:    "stable",
		Constraint: "^1",
	})
	if err != nil {
		t.Fatalf("CheckUpgrade() error = %v", err)
	}
	if !offered || release == nil {
		t.Fatalf("offered = %v, release = %+v", offered, release)
	}
	if gotPath != "/v1/accounts/acct-123/releases/actions/upgrade" {
		t.Errorf("path = %s", gotPath)
	}
	want := map[string]string{
		"product": "prod-uuid", "platform": "darwin", "filetype": "dmg",
		"version": "1.9.0", "channel": "stable", "constraint": "^1",
	}
	for key, value := range want {
		if got := gotQuery.Get(key); got != value {
			t.Errorf("query[%s] = %q, want %q", key, got, value)
		}
	}
}

func TestCheckUpgrade_DecodesTheCamelCaseResourceWithBareTimestamps(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + serverReleaseJSON + `}`))
	})
	defer closeFn()

	release, _, err := c.CheckUpgrade(context.Background(), UpgradeOptions{
		ProductID: "prod-uuid", Platform: "darwin", Filetype: "dmg", Version: "1.9.0",
	})
	if err != nil {
		t.Fatalf("CheckUpgrade() error = %v", err)
	}
	// productId is camelCase because the struct is...
	if release.Attributes.ProductID != "prod-uuid" {
		t.Errorf("ProductID = %q — the wire name is camelCase productId", release.Attributes.ProductID)
	}
	// ...and created/updated are bare because a per-field rename beats
	// rename_all. Reading them as createdAt/updatedAt yields two empty
	// strings and no error, which is why this is asserted rather than
	// assumed.
	if release.Attributes.Created != "2026-01-01T00:00:00Z" {
		t.Errorf("Created = %q, want the bare `created` wire name", release.Attributes.Created)
	}
	if release.Attributes.Updated != "2026-01-02T00:00:00Z" {
		t.Errorf("Updated = %q, want the bare `updated` wire name", release.Attributes.Updated)
	}
	if release.Attributes.Tag != nil {
		t.Errorf("Tag = %v, want nil for an omitted field", *release.Attributes.Tag)
	}
}

// The two ways to get this resource's casing wrong, pinned as failures.
func TestCheckUpgrade_RejectsBothUniformCasingRules(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "snake_case everywhere loses productId",
			body: `{"id":"r","type":"releases","attributes":{"product_id":"prod-uuid","version":"2.0.0","channel":"stable","status":"PUBLISHED","metadata":{},"created":"c","updated":"u"}}`,
		},
		{
			name: "camelCase everywhere loses the timestamps",
			body: `{"id":"r","type":"releases","attributes":{"productId":"prod-uuid","version":"2.0.0","channel":"stable","status":"PUBLISHED","metadata":{},"createdAt":"c","updatedAt":"u"}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.api+json")
				_, _ = w.Write([]byte(`{"data":` + tc.body + `}`))
			})
			defer closeFn()

			release, _, err := c.CheckUpgrade(context.Background(), UpgradeOptions{
				ProductID: "p", Platform: "darwin", Filetype: "dmg", Version: "1.0.0",
			})
			if err != nil {
				t.Fatalf("CheckUpgrade() error = %v", err)
			}
			lost := release.Attributes.ProductID == "" ||
				release.Attributes.Created == "" || release.Attributes.Updated == ""
			if !lost {
				t.Fatal("a uniformly-cased body decoded fully; the per-field renames are no longer being honoured")
			}
		})
	}
}

func TestCheckUpgrade_TreatsA204AsNotOfferedRatherThanUpToDate(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer closeFn()

	release, offered, err := c.CheckUpgrade(context.Background(), UpgradeOptions{
		ProductID: "p", Platform: "darwin", Filetype: "dmg", Version: "1.0.0",
	})
	// A 204 has no body at all, so a decoder that assumes JSON breaks here.
	if err != nil {
		t.Fatalf("CheckUpgrade() error = %v, want nil for a 204", err)
	}
	if offered || release != nil {
		t.Fatalf("offered = %v, release = %+v", offered, release)
	}
}

func TestCheckUpgrade_ServerRefusals(t *testing.T) {
	tests := []struct {
		want   error
		name   string
		body   string
		status int
	}{
		{
			want:   ErrForbidden,
			name:   "suspended license is refused before the 204 branch",
			status: http.StatusForbidden,
			body:   `{"errors":[{"status":"403","code":"FORBIDDEN","title":"Forbidden","detail":"The license is suspended"}]}`,
		},
		{
			want:   ErrNotFound,
			name:   "unknown product",
			status: http.StatusNotFound,
			body:   `{"errors":[{"status":"404","code":"NOT_FOUND","title":"Not Found","detail":"product"}]}`,
		},
		{
			want:   ErrUnauthorized,
			name:   "licensed product with no usable credential",
			status: http.StatusUnauthorized,
			body:   `{"errors":[{"status":"401","code":"UNAUTHORIZED","title":"Unauthorized","detail":"A valid license is required"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.api+json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			defer closeFn()

			_, offered, err := c.CheckUpgrade(context.Background(), UpgradeOptions{
				ProductID: "p", Platform: "darwin", Filetype: "dmg", Version: "1.0.0",
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("errors.Is(err, %v) = false, err = %v", tc.want, err)
			}
			if offered {
				t.Error("offered = true on an error")
			}
		})
	}
}

func TestCheckUpgrade_PlainTextBadRequestDoesNotCrashTheDecoder(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Failed to deserialize query string"))
	})
	defer closeFn()

	_, _, err := c.CheckUpgrade(context.Background(), UpgradeOptions{
		ProductID: "p", Platform: "darwin", Filetype: "dmg", Version: "1.0.0",
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an *APIError", err)
	}
	if apiErr.Err.Code != "UNKNOWN" || apiErr.HTTPStatus != http.StatusBadRequest {
		t.Errorf("code = %q, status = %d", apiErr.Err.Code, apiErr.HTTPStatus)
	}
}

func TestCheckUpgrade_RefusesAnIncompleteQueryLocally(t *testing.T) {
	complete := UpgradeOptions{ProductID: "p", Platform: "darwin", Filetype: "dmg", Version: "1.0.0"}
	tests := []struct {
		mutate func(*UpgradeOptions)
		name   string
	}{
		{mutate: func(o *UpgradeOptions) { o.ProductID = "" }, name: "product"},
		{mutate: func(o *UpgradeOptions) { o.Platform = "" }, name: "platform"},
		{mutate: func(o *UpgradeOptions) { o.Filetype = "" }, name: "filetype"},
		{mutate: func(o *UpgradeOptions) { o.Version = "" }, name: "version"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusNoContent)
			})
			defer closeFn()

			opts := complete
			tc.mutate(&opts)
			if _, _, err := c.CheckUpgrade(context.Background(), opts); err == nil {
				t.Fatal("CheckUpgrade() error = nil for an incomplete query")
			}
			if calls != 0 {
				t.Errorf("made %d requests; the server answers this one in plain text, so refuse it locally", calls)
			}
		})
	}
}
