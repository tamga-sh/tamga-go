// Package crypto — rsa.go wraps stdlib crypto/rsa for RSA-PKCS1v1.5 and
// RSA-PSS signature verification, both SHA-256.
//
// Used by checkout_machine.go (RSA_2048_PKCS1_SIGN / RSA_2048_PKCS1_PSS_SIGN)
// and shared with proof.go's always-PKCS1v1.5 offline-proof verification —
// a single implementation, not a second copy.
//
// ⚠️ RSA_2048_JWT_RS256 is not supported for machine files — the server
// returns 422 SCHEME_NOT_SUPPORTED for it. This package has no JWT
// awareness at all; checkout_machine.go's dispatcher must reject that
// scheme up front, before ever reaching this file, rather than attempt JWT
// parsing here.
package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
)

// VerifyRSAPKCS1v15 verifies an RSA-PKCS1v1.5/SHA-256 signature over
// message (this function hashes message itself — callers pass the raw
// signed bytes, not a pre-computed digest).
func VerifyRSAPKCS1v15(pub *rsa.PublicKey, message, sig []byte) error {
	digest := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// VerifyRSAPSS verifies an RSA-PSS/SHA-256 signature over message (hashed
// internally, same message-not-digest contract as VerifyRSAPKCS1v15).
// Salt length is auto-detected from the signature (rsa.PSSSaltLengthAuto),
// so this verifies correctly regardless of which salt length the signer
// used — including the "salt length equals hash length" convention most
// non-Go RSA-PSS implementations (aws-lc-rs among them) default to.
func VerifyRSAPSS(pub *rsa.PublicKey, message, sig []byte) error {
	digest := sha256.Sum256(message)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	return rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, opts)
}
