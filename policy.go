// Package tamga — policy.go holds the policy-derived enums and the partial
// Policy resource a validating client needs to interpret a license's
// behavior, not just its ValidationCode (Tamga API protocol specification
// §10).
package tamga

import "encoding/json"

// LicenseScheme is the signing scheme used for license/machine checkout
// files (checkout_license.go, checkout_machine.go) and — always, regardless
// of this value — machine offline proofs (proof.go). The wire field
// (license.scheme / policy.scheme) is a nullable string; an empty/unset
// value means "legacy plain/unsigned key" and has no corresponding
// constant here.
type LicenseScheme string

const (
	// SchemeEd25519Sign is Ed25519. The machine-file default when a
	// license has no scheme set (Tamga API protocol specification §10).
	SchemeEd25519Sign LicenseScheme = "ED25519_SIGN"
	// SchemeRSA2048PKCS1Sign is RSA-2048 PKCS#1 v1.5 / SHA-256.
	SchemeRSA2048PKCS1Sign LicenseScheme = "RSA_2048_PKCS1_SIGN"
	// SchemeRSA2048PKCS1PSSSign is RSA-2048 PSS / SHA-256.
	SchemeRSA2048PKCS1PSSSign LicenseScheme = "RSA_2048_PKCS1_PSS_SIGN"
	// SchemeECDSAP256Sign is ECDSA P-256 / SHA-256 (ASN.1 DER signature).
	SchemeECDSAP256Sign LicenseScheme = "ECDSA_P256_SIGN"
	// SchemeRSA2048JWTRS256 is an RS256-signed JWT. Modeled for
	// completeness only: explicitly rejected client-side for machine
	// checkout verification (checkout_machine.go) before any crypto is
	// attempted, mirroring the server's own 422 SCHEME_NOT_SUPPORTED for
	// this scheme specifically — never dispatched to a verifier.
	SchemeRSA2048JWTRS256 LicenseScheme = "RSA_2048_JWT_RS256"
)

// OverageStrategy controls how far over policy.max_* a machine/core/
// memory/disk/process count is still permitted before validation fails
// with the corresponding TOO_MANY_*/TOO_MUCH_* ValidationCode. It never
// applies to `uses`, which the server always compares with strict `>=`
// regardless of strategy.
type OverageStrategy string

const (
	// OverageNone enforces the limit strictly: count <= max (×1).
	OverageNone OverageStrategy = "NO_OVERAGE"
	// Overage125x allows up to 125% of the limit.
	Overage125x OverageStrategy = "ALLOW_1_25X_OVERAGE"
	// Overage15x allows up to 150% of the limit.
	Overage15x OverageStrategy = "ALLOW_1_5X_OVERAGE"
	// Overage2x allows up to 200% of the limit.
	Overage2x OverageStrategy = "ALLOW_2X_OVERAGE"
	// OverageAlwaysAllow skips limit enforcement entirely.
	OverageAlwaysAllow OverageStrategy = "ALWAYS_ALLOW_OVERAGE"
)

// Allows reports whether count is permitted under this strategy given a
// max limit, mirroring the server's own OverageStrategy::allows exactly
// (including its float64 multiplication) so a client-side pre-check
// reaches the identical verdict.
func (s OverageStrategy) Allows(count, max int64) bool {
	switch s {
	case Overage125x:
		return float64(count) <= float64(max)*1.25
	case Overage15x:
		return float64(count) <= float64(max)*1.5
	case Overage2x:
		return float64(count) <= float64(max)*2.0
	case OverageAlwaysAllow:
		return true
	default: // OverageNone and any unrecognized value.
		return count <= max
	}
}

// HeartbeatCullStrategy controls what happens to a machine row once its
// heartbeat window elapses — but only on a policy that has opted in.
//
// ⚠️ The strategy is inert unless PolicyAttributes.RequireHeartbeat is
// true. The server's culling job early-returns for any policy with
// require_heartbeat = false, and that column defaults to FALSE, so on a
// default policy no machine is ever culled under either value. A machine
// that stops pinging under such a policy reports HeartbeatDead
// indefinitely while its row and its seat stay exactly where they were.
// DEAD is a staleness report about last_heartbeat_at, never proof that
// this strategy ran — see HeartbeatStatus.
type HeartbeatCullStrategy string

const (
	// HeartbeatCullDeactivateDead deletes the machine row once dead —
	// only on a policy that sets RequireHeartbeat.
	HeartbeatCullDeactivateDead HeartbeatCullStrategy = "DEACTIVATE_DEAD"
	// HeartbeatCullKeepDead keeps the dead machine row. This is also the
	// effective behavior of every policy that leaves RequireHeartbeat
	// false, whatever its configured strategy claims.
	HeartbeatCullKeepDead HeartbeatCullStrategy = "KEEP_DEAD"
)

// HeartbeatResurrectionStrategy is the grace window after a machine's
// heartbeat window elapses during which a new ping revives it instead of
// HeartbeatCullStrategy taking effect.
//
// It bounds only how long the culling job tolerates a stale row, and that
// job runs at all only under RequireHeartbeat. It does not gate
// Client.PingHeartbeat: a ping against a DEAD machine writes
// last_heartbeat_at unconditionally, with no resurrection check, so for
// as long as the row exists the ping brings the machine back regardless
// of this setting.
type HeartbeatResurrectionStrategy string

// Heartbeat resurrection grace-window constants — see
// HeartbeatResurrectionStrategy's doc comment.
const (
	HeartbeatResurrectionNone   HeartbeatResurrectionStrategy = "NO_REVIVE"
	HeartbeatResurrection1Min   HeartbeatResurrectionStrategy = "1_MINUTE_REVIVE"
	HeartbeatResurrection2Min   HeartbeatResurrectionStrategy = "2_MINUTE_REVIVE"
	HeartbeatResurrection5Min   HeartbeatResurrectionStrategy = "5_MINUTE_REVIVE"
	HeartbeatResurrection10Min  HeartbeatResurrectionStrategy = "10_MINUTE_REVIVE"
	HeartbeatResurrection15Min  HeartbeatResurrectionStrategy = "15_MINUTE_REVIVE"
	HeartbeatResurrectionAlways HeartbeatResurrectionStrategy = "ALWAYS_REVIVE"
)

// CheckInInterval is the check-in cadence unit. ⚠️ Wire values are
// lowercase ("day"/"week"/"month"/"year") — inconsistent with the
// SCREAMING_SNAKE_CASE convention every other enum in this package uses.
type CheckInInterval string

// Check-in cadence constants — see CheckInInterval's doc comment for the
// lowercase-casing gotcha.
const (
	CheckInIntervalDay   CheckInInterval = "day"
	CheckInIntervalWeek  CheckInInterval = "week"
	CheckInIntervalMonth CheckInInterval = "month"
	CheckInIntervalYear  CheckInInterval = "year"
)

// ExpirationStrategy is a free-text policy field the server branches on via
// literal string match rather than a closed enum — an unrecognized value
// is not a decode error (it's just a string) since the server itself
// doesn't validate against a fixed set either. Treat any value outside the
// named constants as "deny/default" (Tamga API protocol specification §10).
type ExpirationStrategy string

// Named ExpirationStrategy values the server documents — see
// ExpirationStrategy's doc comment; any other wire value is valid too.
//
// The strategy decides whether an EXPIRED license can still authenticate
// at all, which is a coarser question than what a validate call reports.
// RESTRICT_ACCESS, MAINTAIN_ACCESS, and ALLOW_ACCESS all still
// authenticate — the license simply validates as
// ValidationCodeExpired. Only ExpirationRevokeAccess (and any
// unrecognized value, which the server fails closed on) refuses at the
// door with 401 LICENSE_EXPIRED, matching ErrLicenseExpired.
const (
	ExpirationRestrictAccess ExpirationStrategy = "RESTRICT_ACCESS" // default
	ExpirationMaintainAccess ExpirationStrategy = "MAINTAIN_ACCESS"
	ExpirationAllowAccess    ExpirationStrategy = "ALLOW_ACCESS"
	// ExpirationRevokeAccess is the only strategy under which an expired
	// license stops authenticating: every request fails 401
	// LICENSE_EXPIRED (ErrLicenseExpired) instead of reaching validation.
	ExpirationRevokeAccess ExpirationStrategy = "REVOKE_ACCESS"
)

// RenewalBasis is a free-text policy field — see ExpirationStrategy's doc
// comment for the general rationale.
type RenewalBasis string

// Named RenewalBasis values the server documents — see RenewalBasis's doc
// comment; any other wire value is valid too.
const (
	RenewalFromExpiry RenewalBasis = "FROM_EXPIRY" // default
	RenewalFromNow    RenewalBasis = "FROM_NOW"
)

// AuthenticationStrategy decides whether a raw license key is accepted as
// a credential for the licenses under this policy. It is a free-text
// policy field — see ExpirationStrategy's doc comment for the general
// rationale.
//
// ⚠️ This is a hard precondition for this SDK's default transport, and it
// is OFF by default. License-key authentication (WithLicenseKey /
// LicenseKeyAuth) is accepted only under AuthStrategyLicense or
// AuthStrategyMixed. The column defaults to TOKEN, so on a
// freshly-created policy every license-key request fails with 401
// LICENSE_NOT_ALLOWED (ErrLicenseNotAllowed) until an operator switches
// the policy over.
//
// Treat that 401 as a configuration problem, not a transient auth
// failure: retrying, refreshing, or re-entering the key changes nothing.
type AuthenticationStrategy string

// Named AuthenticationStrategy values the server documents — see
// AuthenticationStrategy's doc comment; any other wire value is valid too.
const (
	// AuthStrategyToken is the server default. License-key auth is
	// REFUSED under it — tokens only.
	AuthStrategyToken AuthenticationStrategy = "TOKEN" // default
	// AuthStrategyLicense accepts license-key auth.
	AuthStrategyLicense AuthenticationStrategy = "LICENSE"
	// AuthStrategyMixed accepts license-key auth alongside tokens.
	AuthStrategyMixed AuthenticationStrategy = "MIXED"
	// AuthStrategyNone behaves exactly like AuthStrategyToken at the
	// authentication gate: license-key auth is refused with 401
	// LICENSE_NOT_ALLOWED. The name suggests "no authentication
	// required"; it does not mean that.
	AuthStrategyNone AuthenticationStrategy = "NONE"
)

// Policy is the partial `policies` JSON:API resource attribute set this SDK
// models (Tamga API protocol specification §10). ⚠️ The GET response omits
// max_memory and max_disk even though both are enforced during validation
// — this SDK cannot introspect those two limits client-side, only observe
// TOO_MUCH_MEMORY/TOO_MUCH_DISK if validation fails, so neither field is
// modeled here at all (not merely left nil).
type Policy struct {
	ID         string           `json:"id"`
	Type       string           `json:"type"`
	Attributes PolicyAttributes `json:"attributes"`
}

// PolicyAttributes is the attribute bag of a Policy resource.
//
// heartbeat_cull_strategy and overage_strategy/heartbeat_resurrection_strategy
// are intentionally kept as raw strings (HeartbeatCullStrategyRaw,
// OverageStrategyRaw, HeartbeatResurrectionStrategyRaw) rather than the
// typed enums above: freshly-created policies default overage_strategy to
// the non-existent string "DENY_ACCESS" and heartbeat_resurrection_strategy
// to the non-existent string "NO_RESURRECTION" (the Tamga API protocol
// specification's Known Server-Side Gaps #9) — decoding straight into the
// typed enum would still technically succeed (Go string-backed types
// accept any string), but callers reading the raw field and comparing it
// against the OverageNone/HeartbeatResurrectionNone constants directly
// would get a false "not equal" without calling EffectiveOverageStrategy/
// EffectiveResurrectionStrategy first. Keeping these three fields raw-typed
// documents at the type level that a translation step is required.
//
// RequireHeartbeat is the master switch for heartbeat enforcement and it
// defaults to FALSE. While it is false the server's culling job
// early-returns and HeartbeatCullStrategy/HeartbeatResurrectionStrategy
// are both dead letters — no machine on this policy is ever culled, no
// matter how long it has reported HeartbeatDead. Read it before
// concluding anything from a machine's heartbeat status.
type PolicyAttributes struct {
	CheckInInterval                  *CheckInInterval       `json:"check_in_interval"`
	MaxUsers                         *int32                 `json:"max_users"`
	Duration                         *int64                 `json:"duration"`
	MaxProcesses                     *int32                 `json:"max_processes"`
	MaxUses                          *int32                 `json:"max_uses"`
	Scheme                           *string                `json:"scheme"`
	MaxCores                         *int32                 `json:"max_cores"`
	MaxMachines                      *int32                 `json:"max_machines"`
	HeartbeatDuration                *int32                 `json:"heartbeat_duration"`
	CheckInIntervalCount             *int32                 `json:"check_in_interval_count"`
	OverageStrategyRaw               string                 `json:"overage_strategy"`
	RenewalBasis                     RenewalBasis           `json:"renewal_basis"`
	Updated                          string                 `json:"updated"`
	Created                          string                 `json:"created"`
	HeartbeatCullStrategyRaw         string                 `json:"heartbeat_cull_strategy"`
	HeartbeatResurrectionStrategyRaw string                 `json:"heartbeat_resurrection_strategy"`
	MachineUniquenessStrategy        string                 `json:"machine_uniqueness_strategy"`
	ExpirationStrategy               ExpirationStrategy     `json:"expiration_strategy"`
	ExpirationBasis                  string                 `json:"expiration_basis"`
	Name                             string                 `json:"name"`
	AuthenticationStrategy           AuthenticationStrategy `json:"authentication_strategy"`
	ProductID                        string                 `json:"product_id"`
	Metadata                         json.RawMessage        `json:"metadata"`
	UsePool                          bool                   `json:"use_pool"`
	Encrypted                        bool                   `json:"encrypted"`
	Floating                         bool                   `json:"floating"`
	Strict                           bool                   `json:"strict"`
	RequireCheckIn                   bool                   `json:"require_check_in"`
	Protected                        bool                   `json:"protected"`
	RequireHeartbeat                 bool                   `json:"require_heartbeat"`
}

// EffectiveOverageStrategy maps a policy's raw overage_strategy wire string
// to a real OverageStrategy variant, falling back to OverageNone for any
// unrecognized value — including the real-world policy-create default
// "DENY_ACCESS", which is not a real OverageStrategy variant and which the
// server itself silently treats as NoOverage (the Tamga API protocol
// specification's Known Server-Side Gaps #9). Do not surface the raw
// string as if it meant "deny everything," which is what the field name
// implies and is not what actually happens.
func EffectiveOverageStrategy(raw string) OverageStrategy {
	switch OverageStrategy(raw) {
	case Overage125x, Overage15x, Overage2x, OverageAlwaysAllow:
		return OverageStrategy(raw)
	default:
		return OverageNone
	}
}

// EffectiveResurrectionStrategy maps a policy's raw
// heartbeat_resurrection_strategy wire string to a real
// HeartbeatResurrectionStrategy variant, falling back to
// HeartbeatResurrectionNone for any unrecognized value — including the
// real-world policy-create default "NO_RESURRECTION", which is not a real
// variant and which the server itself silently treats as NoRevive
// (the Tamga API protocol specification's Known Server-Side Gaps #9).
func EffectiveResurrectionStrategy(raw string) HeartbeatResurrectionStrategy {
	switch HeartbeatResurrectionStrategy(raw) {
	case HeartbeatResurrection1Min, HeartbeatResurrection2Min, HeartbeatResurrection5Min,
		HeartbeatResurrection10Min, HeartbeatResurrection15Min, HeartbeatResurrectionAlways:
		return HeartbeatResurrectionStrategy(raw)
	default:
		return HeartbeatResurrectionNone
	}
}
