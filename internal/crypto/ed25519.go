// Package crypto — ed25519.go is a thin wrapper over stdlib crypto/ed25519.
//
// Used by checkout_license.go (always) and checkout_machine.go (when
// LicenseScheme is ED25519_SIGN). This package does not itself decide
// whether to sign/verify over a base64 string or its decoded bytes — the
// caller is responsible for passing the correct message bytes; see
// checkout_license.go's doc comment for that gotcha (⚠️ the .lic/.machine
// signature covers the ASCII/UTF-8 bytes of the base64 STRING itself, not
// its decoded bytes — this is the single most important implementation
// trap in the whole SDK, documented at the call site in
// checkout_license.go/checkout_machine.go, not re-derived here).
package crypto

import "crypto/ed25519"

// VerifyEd25519 verifies an Ed25519 signature over message using the
// account's raw 32-byte public key. Delegates to stdlib crypto/ed25519's
// own verify primitive, which runs in constant time with respect to the
// signature — never hand-roll a byte comparison here, which would risk a
// timing side channel.
func VerifyEd25519(pub ed25519.PublicKey, message, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}
