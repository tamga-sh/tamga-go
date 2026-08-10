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
	"crypto/sha256"
)

// VerifyECDSA verifies an ECDSA P-256/SHA-256 signature (ASN.1 DER
// encoded, per this file's doc comment) over message (hashed internally —
// callers pass the raw signed bytes, not a pre-computed digest).
func VerifyECDSA(pub *ecdsa.PublicKey, message, sig []byte) bool {
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}
