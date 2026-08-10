package tamga

import (
	"context"
	"encoding/json"
	"fmt"
)

// License is the `licenses` JSON:API resource (docs/sdk.md §2). Field set
// matches the server's actual LicenseResource/LicenseAttributes serializer
// — notably, no `relationships` object exists on this resource today.
//
// IDs (License.ID, and every other resource/relationship ID in this
// package) are modeled as plain strings, not a dedicated UUID type: this
// package's only external dependency is golang.org/x/crypto (for HKDF, see
// internal/crypto/hkdf.go and CLAUDE.md's "Critical Dependency Notes") —
// adding google/uuid or a similar package solely to wrap an
// already-string-shaped wire value would violate that single-dependency
// design deliberately recorded in this repo's CLAUDE.md and go.mod. This
// is a documented deviation from docs/plans/tamga-go.plan.md's literal
// `uuid.UUID` field-type wording in Section C/E/F/etc. — ground truth here
// is this repo's own scaffolded go.mod/CLAUDE.md, which predates and
// overrides the plan's abbreviated type sketches.
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
// Only Product/Policy/User/Environment are actually enforced server-side
// today; Entitlements/Fingerprint/Version/Checksum are parsed but silently
// ignored (docs/sdk.md §2). Model them here for forward-compatibility, but
// never advertise them as functioning constraints.
type Scope struct {
	Product      *string  `json:"product,omitempty"`
	Policy       *string  `json:"policy,omitempty"`
	User         *string  `json:"user,omitempty"`
	Environment  *string  `json:"environment,omitempty"`
	Fingerprint  *string  `json:"fingerprint,omitempty"`
	Version      *string  `json:"version,omitempty"`
	Checksum     *string  `json:"checksum,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
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
	// which fields are actually enforced today.
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
// envelope (docs/sdk.md §1/§2) — decodeFlat implements that special case.
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
