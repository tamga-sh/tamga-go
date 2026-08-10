// ed25519.go will hold a thin wrapper over stdlib crypto/ed25519:
//
//	Verify(pub ed25519.PublicKey, message, sig []byte) bool
//
// Used by checkout_license.go (always) and checkout_machine.go (when
// LicenseScheme is ED25519_SIGN). The caller is responsible for passing
// the correct message bytes — this package does not itself decide whether
// to sign/verify over a base64 string or its decoded bytes; see
// checkout_license.go's doc comment for that gotcha.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section E; tests will verify against RFC
// 8032 vectors (internal/crypto/ed25519_test.go).
package crypto
