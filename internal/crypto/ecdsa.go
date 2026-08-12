// Package crypto — ecdsa.go wraps stdlib crypto/ecdsa for the
// ECDSA_P256_SIGN machine checkout signature scheme.
//
// Wire signature encoding is ASN.1 DER (matching the server's aws-lc-rs
// ECDSA_P256_SHA256_ASN1 verifier), not the raw r‖s concatenation some
// other ECDSA wire formats use — VerifyECDSA uses stdlib's
// ecdsa.VerifyASN1 specifically, not a raw-r‖s parser, to match.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
)

// VerifyECDSA verifies an ECDSA P-256/SHA-256 signature (ASN.1 DER
// encoded, per this file's doc comment) over message (hashed internally —
// callers pass the raw signed bytes, not a pre-computed digest).
func VerifyECDSA(pub *ecdsa.PublicKey, message, sig []byte) bool {
	// SECURITY: pub's curve comes from whatever the caller parsed (e.g.
	// x509.ParsePKIXPublicKey, which embeds its own curve OID) -- without
	// this check, a validly-signed message from any other curve (P-384,
	// etc.) would verify successfully here, since SHA-256 is just the
	// digest algorithm and is independent of curve choice. Found via
	// audit; see ecdsa_test.go's TestVerifyECDSA_RejectsWrongCurve.
	if pub.Curve != elliptic.P256() {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}
