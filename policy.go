// policy.go will hold the policy-derived enums and the partial Policy
// resource that a validating client needs to interpret a license's
// behavior, not just its ValidationCode (docs/sdk.md §10):
//
//   - LicenseScheme (ED25519_SIGN, RSA_2048_PKCS1_SIGN,
//     RSA_2048_PKCS1_PSS_SIGN, ECDSA_P256_SIGN, RSA_2048_JWT_RS256 — the
//     last explicitly rejected for machine checkout)
//   - OverageStrategy (NO_OVERAGE, ALLOW_1_25X/1_5X/2X_OVERAGE,
//     ALWAYS_ALLOW_OVERAGE — never applies to `uses`, which is always a
//     strict >= comparison)
//   - HeartbeatCullStrategy, HeartbeatResurrectionStrategy
//   - check_in_interval (lowercase, inconsistent with every other enum
//     here), and the unbacked free-text fields expiration_strategy /
//     renewal_basis / authentication_strategy (branched by literal string
//     match server-side, no real enum backing them)
//   - EffectiveOverageStrategy / EffectiveResurrectionStrategy helpers,
//     which must map the actual (non-enum) policy-create defaults
//     "DENY_ACCESS" / "NO_RESURRECTION" to NO_OVERAGE / NO_REVIVE
//     semantics — see docs/sdk.md's Known Server-Side Gaps item 9
//
// Doc note carried forward from docs/sdk.md §10: the policy GET response
// omits max_memory and max_disk even though both are enforced during
// validation — this SDK cannot introspect those two limits client-side.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section K.
package tamga
