// proof.go will hold GenerateOfflineProof (POST
// .../machines/{id}/actions/generate-offline-proof, body
// {"meta": {"dataset": {...}}}, defaulting to {} when dataset is nil),
// ParseProof (splitting the "v1x0." prefix from the base64 signature), and
// VerifyOfflineProof.
//
// Always signed with RSA-2048 PKCS#1 v1.5 / SHA-256, regardless of the
// license's scheme — unlike checkout_machine.go, this is never
// scheme-driven (docs/sdk.md §7).
//
// The central gotcha this file must get exactly right: the signature
// covers {"account":{"id":...},"machine":{"id":...,"fingerprint":...},
// "dataset":<client dataset>} serialized in the server's exact field
// order — a verifying implementation must reproduce that serialization,
// not just the same field set, or the signature check fails. Go's default
// encoding/json map-key sorting cannot be relied on for the outer struct;
// this needs an explicit ordered encoder plus a golden-file regression
// test once implemented.
//
// Reuses internal/crypto/rsa.go's PKCS1v15 verifier — a single shared
// implementation with checkout_machine.go's RSA path, not a second copy.
//
// Not implemented yet — scaffold placeholder, and this file's real
// implementation carries a MANDATORY security-reviewer gate before merge.
// See docs/plans/tamga-go.plan.md Section H.
package tamga
