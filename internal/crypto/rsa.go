// rsa.go will hold thin wrappers over stdlib crypto/rsa:
//
//	VerifyPKCS1v15(pub *rsa.PublicKey, hashed, sig []byte) error
//	VerifyPSS(pub *rsa.PublicKey, hashed, sig []byte) error
//
// Both SHA-256. Used by checkout_machine.go (RSA_2048_PKCS1_SIGN /
// RSA_2048_PKCS1_PSS_SIGN) and shared with proof.go's always-PKCS1v15
// offline-proof verification — a single implementation, not a second copy.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section F; tests will verify against known
// test vectors plus negative tampered-signature cases
// (internal/crypto/rsa_test.go).
package crypto
