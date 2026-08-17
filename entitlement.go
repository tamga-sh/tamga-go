package tamga

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Entitlement is the `entitlements` JSON:API resource
// (docs/sdk.md §9). Despite the URL nesting under
// /licenses/{id}/entitlements, list/get on this endpoint return full
// Entitlement resources, not lightweight junction/relationship records.
type Entitlement struct {
	ID         string                `json:"id"`
	Type       string                `json:"type"`
	Attributes EntitlementAttributes `json:"attributes"`
}

// EntitlementAttributes is the attribute bag of an Entitlement resource.
//
// Code is the stable, developer-facing identifier — HasEntitlement matches
// on this field. Name is a display label only and may collide or change
// independently of Code; never match on it.
type EntitlementAttributes struct {
	Name     string          `json:"name"`
	Code     string          `json:"code"`
	Created  string          `json:"created"`
	Updated  string          `json:"updated"`
	Metadata json.RawMessage `json:"metadata"`
}

// ListOptions is the shared keyset-pagination request shape used by
// ListComponents and ListEntitlements (docs/sdk.md §8/§9).
type ListOptions struct {
	After *string
	Limit int
}

// EntitlementPage is a single page of ListEntitlements results.
//
// NextCursor is set to the last item's ID when a full page (Limit items)
// was returned, since these endpoints carry no cursor metadata/links of
// their own — pass it as the next call's ListOptions.After. It is left nil
// on a short/empty page, signaling there is nothing further to fetch.
type EntitlementPage struct {
	NextCursor *string
	Items      []Entitlement
}

// ListEntitlements lists a license's entitlements, keyset-paginated.
// GET /v1/accounts/{account_id}/licenses/{license_id}/entitlements.
func (c *Client) ListEntitlements(ctx context.Context, licenseID string, opts ListOptions) (*EntitlementPage, error) {
	path := fmt.Sprintf("/licenses/%s/entitlements", escapePathSegment(licenseID))
	query := url.Values{}
	if opts.Limit > 0 {
		query.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.After != nil {
		query.Set("page[after]", *opts.After)
	}
	fullPath := path
	if encoded := query.Encode(); encoded != "" {
		fullPath += "?" + encoded
	}
	items, err := decodeJSONAPI[[]Entitlement](ctx, c, "GET", fullPath, nil)
	if err != nil {
		return nil, err
	}
	page := &EntitlementPage{Items: items}
	if opts.Limit > 0 && len(items) == opts.Limit {
		last := items[len(items)-1].ID
		page.NextCursor = &last
	}
	return page, nil
}

// GetEntitlement fetches a single entitlement by ID.
// GET /v1/accounts/{account_id}/licenses/{license_id}/entitlements/{entitlement_id}.
func (c *Client) GetEntitlement(ctx context.Context, licenseID, entitlementID string) (*Entitlement, error) {
	path := fmt.Sprintf("/licenses/%s/entitlements/%s", escapePathSegment(licenseID), escapePathSegment(entitlementID))
	entitlement, err := decodeJSONAPI[Entitlement](ctx, c, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	return &entitlement, nil
}

// entitlementCacheTTL is how long HasEntitlement's per-license entitlement
// list cache stays fresh before the next call triggers a refetch.
const entitlementCacheTTL = 60 * time.Second

// entitlementCacheEntry holds one license's cached entitlement codes plus
// when the entry was fetched.
type entitlementCacheEntry struct {
	codes     map[string]struct{}
	fetchedAt time.Time
}

// entitlementCache is a simple in-memory TTL cache of per-license
// entitlement code sets, backing HasEntitlement. Safe for concurrent use.
//
// Entries are only evicted by TTL staleness (entitlementCacheTTL) on the
// next HasEntitlement call for that license, or explicitly via
// InvalidateEntitlementCache — there is no bounded-size/LRU eviction. This
// is a deliberate scope decision, not an oversight: this cache is keyed by
// license ID, and a single embedded/client SDK instance realistically
// validates a small, bounded number of distinct licenses over its
// lifetime (typically one — the license the host application itself is
// running under) — not an open-ended set driven by untrusted input where
// unbounded growth would be a real memory-exhaustion concern. If a future
// use case needs many distinct licenses tracked concurrently (e.g. a
// server-side integration validating licenses on behalf of many
// customers), add bounded eviction then; building it speculatively today
// would be complexity without a driving requirement.
type entitlementCache struct {
	entries map[string]entitlementCacheEntry
	mu      sync.Mutex
}

// entitlementCacheFor returns c's lazily-initialized entitlement cache.
// Client is constructed via New only, so this always starts nil; the
// lock-protected lazy-init pattern here avoids requiring New to always
// allocate a cache map even for callers who never use HasEntitlement.
func (c *Client) entitlementCacheFor() *entitlementCache {
	c.entCacheOnce.Do(func() {
		c.entCache = &entitlementCache{entries: make(map[string]entitlementCacheEntry)}
	})
	return c.entCache
}

// HasEntitlement reports whether licenseID's entitlement list contains an
// entitlement with the given code (the stable, developer-facing
// identifier) — matching on Code even when a different entitlement's Name
// happens to equal code, and never matching on Name itself.
//
// Backed by an in-memory TTL cache (entitlementCacheTTL) of the license's
// entitlement codes: a call within the TTL of a previous call for the same
// licenseID reuses the cached set instead of making a second HTTP call.
// Fetches at most one page (limit 100, the server's own max page size);
// for licenses with more entitlements than fit on one page, use
// ListEntitlements directly and paginate.
func (c *Client) HasEntitlement(ctx context.Context, licenseID, code string) (bool, error) {
	cache := c.entitlementCacheFor()

	cache.mu.Lock()
	entry, ok := cache.entries[licenseID]
	fresh := ok && time.Since(entry.fetchedAt) < entitlementCacheTTL
	cache.mu.Unlock()

	if !fresh {
		page, err := c.ListEntitlements(ctx, licenseID, ListOptions{Limit: 100})
		if err != nil {
			return false, err
		}
		codes := make(map[string]struct{}, len(page.Items))
		for _, e := range page.Items {
			codes[e.Attributes.Code] = struct{}{}
		}
		entry = entitlementCacheEntry{codes: codes, fetchedAt: time.Now()}
		cache.mu.Lock()
		cache.entries[licenseID] = entry
		cache.mu.Unlock()
	}

	_, found := entry.codes[code]
	return found, nil
}

// InvalidateEntitlementCache drops the cached entitlement list for
// licenseID, forcing the next HasEntitlement call to refetch regardless of
// TTL — the explicit invalidation hatch for the in-memory cache
// HasEntitlement reads from.
func (c *Client) InvalidateEntitlementCache(licenseID string) {
	cache := c.entitlementCacheFor()
	cache.mu.Lock()
	delete(cache.entries, licenseID)
	cache.mu.Unlock()
}
