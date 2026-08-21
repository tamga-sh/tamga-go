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
// (Tamga API protocol specification §9). Despite the URL nesting under
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
//
// Inherited reports whether the license holds this entitlement through
// its policy rather than by a direct attachment. It is only present on
// the license-scoped list route (ListEntitlements) — account-, policy-,
// and release-scoped entitlement responses omit the field entirely, which
// is why it is a *bool: nil means "the server did not say", not false.
//
// It gates three things. An inherited entitlement cannot be detached from
// the license (403 POLICY_ENTITLEMENT); attaching it directly on top is
// refused with 422 ENTITLEMENT_ALREADY_INHERITED; and GetEntitlement
// returns 404 for it — see that method's doc comment.
type EntitlementAttributes struct {
	// Inherited leads the struct only to satisfy govet's fieldalignment
	// check; field order here carries no wire meaning.
	Inherited *bool           `json:"inherited,omitempty"`
	Name      string          `json:"name"`
	Code      string          `json:"code"`
	Created   string          `json:"created"`
	Updated   string          `json:"updated"`
	Metadata  json.RawMessage `json:"metadata"`
}

// ListOptions is the shared keyset-pagination request shape used by
// ListComponents and ListEntitlements (Tamga API protocol specification
// §8/§9).
//
// Limit is clamped server-side to 1..100. Leaving it 0 does NOT mean
// "everything": the server silently falls back to 25 rows, and since
// these routes emit no page metadata and no links, a caller who did not
// pick a limit has no way to tell a complete answer from a truncated one.
// Both list methods therefore send an explicit limit of 100 (the server
// maximum) when Limit is unset, so the page size is always a known
// number.
//
// ⚠️ After works on ListComponents and is inert on ListEntitlements —
// see ListEntitlements' doc comment.
type ListOptions struct {
	After *string
	Limit int
}

// serverMaxPageLimit is the largest page size these keyset list routes
// accept, and the limit both list methods send when the caller did not
// choose one. See ListOptions.
const serverMaxPageLimit = 100

// effectivePageLimit is the page size a list call will actually request:
// the caller's Limit when they set one, otherwise serverMaxPageLimit
// rather than the server's silent 25-row default.
func effectivePageLimit(limit int) int {
	if limit > 0 {
		return limit
	}
	return serverMaxPageLimit
}

// EntitlementPage is a single page of ListEntitlements results.
//
// ⚠️ NextCursor on this type is always nil. It is retained so existing
// code compiles, but this route cannot be paginated — see
// ListEntitlements.
type EntitlementPage struct {
	NextCursor *string
	Items      []Entitlement
}

// ListEntitlements lists a license's entitlements.
// GET /v1/accounts/{account_id}/licenses/{license_id}/entitlements.
//
// ⚠️ This route is NOT paginated, despite accepting the keyset query
// parameters. The listing is a union of the license's direct entitlements
// and the ones inherited from its policy, which a single keyset cursor
// over one table cannot describe, so the server accepts page[after] for
// wire compatibility and then ignores it — the same first page comes back
// forever. A caller who loops "until the page is short" against this
// route never terminates.
//
// Consequently: ListEntitlements never sends page[after] (setting
// ListOptions.After has no effect here), and the returned
// EntitlementPage.NextCursor is unconditionally nil. limit is the only
// bound the server honors, capped at 100.
//
// The hard consequence is that a license with more than 100 effective
// entitlements cannot be enumerated in full through this endpoint at all.
// Treat a negative result — "this code is not in the list" — as
// authoritative only below that ceiling.
//
// ListComponents is a different story: keyset pagination genuinely works
// there, and its After is not inert.
func (c *Client) ListEntitlements(ctx context.Context, licenseID string, opts ListOptions) (*EntitlementPage, error) {
	path := fmt.Sprintf("/licenses/%s/entitlements", escapePathSegment(licenseID))
	query := url.Values{}
	query.Set("limit", strconv.Itoa(effectivePageLimit(opts.Limit)))
	fullPath := path + "?" + query.Encode()
	items, err := decodeJSONAPI[[]Entitlement](ctx, c, "GET", fullPath, nil)
	if err != nil {
		return nil, err
	}
	// NextCursor stays nil on purpose: handing back a cursor this route
	// ignores would invite exactly the loop that never terminates.
	return &EntitlementPage{Items: items}, nil
}

// GetEntitlement fetches a single entitlement by ID.
// GET /v1/accounts/{account_id}/licenses/{license_id}/entitlements/{entitlement_id}.
//
// ⚠️ Resolves DIRECT attachments only. The item route joins just the
// license_entitlements table, so an entitlement that ListEntitlements
// returned with Inherited true — held through the license's policy —
// comes back 404 NOT_FOUND here. List-then-get-each is not a valid
// pattern on this resource; read what you need off the list response.
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
//
// ⚠️ Fetches exactly one page of 100 — the server's max — and that is the
// most this endpoint can ever return, because the route is not paginable
// (see ListEntitlements). A false result is therefore authoritative only
// for licenses holding at most 100 effective entitlements, counting
// policy-inherited ones. Above that ceiling a genuinely-held code can
// report false, and there is no server-side way to enumerate the rest.
// If your product issues more than 100 entitlements to a single license,
// do not gate features on this method.
func (c *Client) HasEntitlement(ctx context.Context, licenseID, code string) (bool, error) {
	cache := c.entitlementCacheFor()

	cache.mu.Lock()
	entry, ok := cache.entries[licenseID]
	fresh := ok && time.Since(entry.fetchedAt) < entitlementCacheTTL
	cache.mu.Unlock()

	if !fresh {
		page, err := c.ListEntitlements(ctx, licenseID, ListOptions{Limit: serverMaxPageLimit})
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
