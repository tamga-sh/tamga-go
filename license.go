package tamga

import (
	"context"
	"encoding/json"
	"fmt"
)

// License is the `licenses` JSON:API resource (Tamga API protocol
// specification §2). Field set matches the server's actual
// LicenseResource/LicenseAttributes serializer — notably, no
// `relationships` object exists on this resource today.
//
// IDs (License.ID, and every other resource/relationship ID in this
// package) are modeled as plain strings, not a dedicated UUID type: this
// package's only external dependency is golang.org/x/crypto (for HKDF, see
// internal/crypto/hkdf.go) — pulling in a UUID package solely to wrap an
// already-string-shaped wire value would spend that single-dependency
// budget on nothing.
type License struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Attributes LicenseAttributes `json:"attributes"`
}

// LicenseAttributes is the attribute bag of a License resource.
type LicenseAttributes struct {
	MaxMachines     *int32          `json:"max_machines"`
	Key             *string         `json:"key"`
	LastCheckInAt   *string         `json:"last_check_in_at"`
	Expiry          *string         `json:"expiry"`
	LastCheckOutAt  *string         `json:"last_check_out_at"`
	Name            *string         `json:"name"`
	LastValidatedAt *string         `json:"last_validated_at"`
	Scheme          *string         `json:"scheme"`
	MaxUsers        *int32          `json:"max_users"`
	MaxUses         *int32          `json:"max_uses"`
	Updated         string          `json:"updated"`
	Created         string          `json:"created"`
	Status          string          `json:"status"`
	Metadata        json.RawMessage `json:"metadata"`
	MachinesCount   int32           `json:"machines_count"`
	Uses            int32           `json:"uses"`
	Protected       bool            `json:"protected"`
	Floating        bool            `json:"floating"`
	Strict          bool            `json:"strict"`
	Encrypted       bool            `json:"encrypted"`
	Suspended       bool            `json:"suspended"`
}

// Scope constrains ValidateByID, sent as meta.scope in the request body.
// Every field is optional — nil/omitted means "no constraint, skip this
// check."
//
// Six of the eight fields are enforced server-side:
//
//   - Product, Policy, User, Environment — compared against the license's
//     own relationships.
//   - Entitlements — a list of entitlement CODEs (the developer-facing
//     identifier, not the UUIDs attach/detach take). Compared
//     case-insensitively and de-duplicated, and satisfied by the union of
//     directly-attached and policy-inherited entitlements. An empty slice
//     asserts nothing. A miss yields ValidationCodeEntitlementsMissing.
//   - Fingerprint — matched against ANY machine registered on the
//     license, regardless of that machine's heartbeat status. This is the
//     anti-key-sharing check. A miss yields
//     ValidationCodeFingerprintScopeMismatch.
//
// ⚠️ Version and Checksum are NOT enforced and are NOT inert either. The
// server rejects the whole request with 422 SCOPE_NOT_SUPPORTED the
// moment either one is present — before running any validation — so the
// caller gets an *APIError and never sees meta.valid at all. Because
// setting them can only break a call that would otherwise have worked,
// this SDK no longer transmits them: both fields are retained for source
// compatibility and are silently dropped by (Scope).MarshalJSON. Setting
// them is a no-op; stop setting them.
type Scope struct {
	Product     *string `json:"product,omitempty"`
	Policy      *string `json:"policy,omitempty"`
	User        *string `json:"user,omitempty"`
	Environment *string `json:"environment,omitempty"`
	Fingerprint *string `json:"fingerprint,omitempty"`
	// Version is deprecated and never sent on the wire: the server
	// answers 422 SCOPE_NOT_SUPPORTED for it and fails the entire
	// validate call. Retained so existing code still compiles.
	//
	// Deprecated: not supported by the server; setting it has no effect.
	Version *string `json:"version,omitempty"`
	// Checksum is deprecated and never sent on the wire, for the same
	// reason as Version.
	//
	// Deprecated: not supported by the server; setting it has no effect.
	Checksum     *string  `json:"checksum,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
}

// MarshalJSON emits the scope object the server actually accepts, with
// Version and Checksum omitted no matter what the caller set them to.
//
// Dropping them silently is the deliberate choice here. The alternative —
// transmitting them and letting the request fail — turns a field that
// used to do nothing into one that breaks the entire validate call with a
// 422, which is a strictly worse outcome for a caller upgrading a patch
// release. Callers who need version or checksum enforcement have to do it
// themselves; the server offers no scope for it.
func (s Scope) MarshalJSON() ([]byte, error) {
	// A distinct type is required: marshaling *Scope from inside
	// Scope.MarshalJSON would recurse forever. `type alias Scope` drops
	// the method set while keeping the field tags.
	type alias struct {
		Product      *string  `json:"product,omitempty"`
		Policy       *string  `json:"policy,omitempty"`
		User         *string  `json:"user,omitempty"`
		Environment  *string  `json:"environment,omitempty"`
		Fingerprint  *string  `json:"fingerprint,omitempty"`
		Entitlements []string `json:"entitlements,omitempty"`
	}
	return json.Marshal(alias{
		Product:      s.Product,
		Policy:       s.Policy,
		User:         s.User,
		Environment:  s.Environment,
		Fingerprint:  s.Fingerprint,
		Entitlements: s.Entitlements,
	})
}

// ValidateByKey validates a license by its raw key.
// POST /v1/accounts/{account_id}/licenses/actions/validate-key.
// No scope support on this endpoint — use ValidateByID for scoped
// validation.
func (c *Client) ValidateByKey(ctx context.Context, key string) (*License, *ValidationMeta, error) {
	body := map[string]any{"key": key}
	license, meta, err := decodeJSONAPIWithMeta[License, ValidationMeta](
		ctx, c, "POST", "/licenses/actions/validate-key", body,
	)
	if err != nil {
		return nil, nil, err
	}
	return &license, &meta, nil
}

// ValidateByIDOptions configures ValidateByID.
type ValidateByIDOptions struct {
	// Scope, if set, constrains validation — see Scope's doc comment for
	// which fields are enforced and why Version/Checksum are never sent.
	Scope *Scope
	// SkipTouch, when true, suppresses the last_validated_at update side
	// effect — useful for polling validity without affecting
	// check-in/telemetry timestamps. Defaults to false.
	SkipTouch bool
}

// ValidateByID validates a license by ID, optionally constrained by a
// Scope. POST /v1/accounts/{account_id}/licenses/{license_id}/actions/validate.
// opts may be nil, in which case the request body is
// `{"meta":{"skip_touch":false}}` (Scope entirely omitted).
func (c *Client) ValidateByID(ctx context.Context, licenseID string, opts *ValidateByIDOptions) (*License, *ValidationMeta, error) {
	meta := map[string]any{"skip_touch": false}
	if opts != nil {
		meta["skip_touch"] = opts.SkipTouch
		if opts.Scope != nil {
			meta["scope"] = opts.Scope
		}
	}
	body := map[string]any{"meta": meta}
	path := fmt.Sprintf("/licenses/%s/actions/validate", escapePathSegment(licenseID))
	license, validationMeta, err := decodeJSONAPIWithMeta[License, ValidationMeta](ctx, c, "POST", path, body)
	if err != nil {
		return nil, nil, err
	}
	return &license, &validationMeta, nil
}

// QuickValidate validates a license by ID and returns only the outcome
// (no license resource) — cheaper than ValidateByID when the caller only
// needs the result. GET /v1/accounts/{account_id}/licenses/{license_id}/actions/validate.
//
// Unlike every other endpoint in this package, the response is plain
// application/json with a flat {ts, valid, detail, code} body — no "data"
// envelope (Tamga API protocol specification §1/§2) — decodeFlat
// implements that special case.
//
// ⚠️ This call normally writes last_validated_at as a side effect, but
// the server SKIPS that write whenever the request carries an Origin
// header — and the response is byte-identical either way, so the caller
// cannot tell which happened. This SDK never sets Origin itself, but a
// proxy, service mesh, or middleware in front of the call can add one,
// and then quick-validate silently stops recording anything.
//
// That silence has teeth: a license with no machines and a NULL
// last_validated_at reports status INACTIVE forever, and the check-in
// overdue worker uses the same column as its baseline, so it keeps firing
// license.check-in-overdue webhooks. CheckIn does not help — it writes
// last_check_in_at, a different column. If you need the write to be
// guaranteed, call ValidateByID (with SkipTouch false) instead: the POST
// route has no Origin branch at all.
func (c *Client) QuickValidate(ctx context.Context, licenseID string) (*ValidationMeta, error) {
	path := fmt.Sprintf("/licenses/%s/actions/validate", escapePathSegment(licenseID))
	meta, err := decodeFlat[ValidationMeta](ctx, c, "GET", path)
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

// CheckIn bumps a license's last_check_in_at.
// POST /v1/accounts/{account_id}/licenses/{license_id}/actions/check-in,
// no body. Returns the updated license resource (no meta on this
// response, unlike validate).
//
// Fails with an error matching ErrCheckInNotRequired (via errors.Is) if
// the license's policy has require_check_in: false — callers should check
// that flag on the license's policy before scheduling periodic check-ins,
// rather than reacting to this error with retry logic.
func (c *Client) CheckIn(ctx context.Context, licenseID string) (*License, error) {
	path := fmt.Sprintf("/licenses/%s/actions/check-in", escapePathSegment(licenseID))
	license, err := decodeJSONAPI[License](ctx, c, "POST", path, nil)
	if err != nil {
		return nil, err
	}
	return &license, nil
}
