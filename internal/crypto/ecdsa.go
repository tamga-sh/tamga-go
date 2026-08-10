// ecdsa.go will hold a thin wrapper over stdlib crypto/ecdsa, P-256 curve:
//
//	Verify(pub *ecdsa.PublicKey, hashed, sig []byte) bool
//
// Used by checkout_machine.go when LicenseScheme is ECDSA_P256_SIGN. The
// exact signature encoding on the wire (ASN.1 DER vs raw r‖s) must be
// documented and tested explicitly once implemented — ECDSA verifiers are
// a common source of wire-format mismatches between languages.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section F; tests will verify against known
// P-256 test vectors (internal/crypto/ecdsa_test.go).
package crypto
