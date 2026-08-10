// aesgcm.go will hold thin wrappers over stdlib crypto/cipher + crypto/aes:
//
//	Open(key [32]byte, nonce, ciphertextAndTag []byte) ([]byte, error)
//	Seal(key [32]byte, nonce, plaintext []byte) (ciphertextAndTag []byte, error)
//
// AES-256-GCM. Open is used by both checkout_license.go (naive key
// derivation, naivekey.go) and checkout_machine.go (HKDF key derivation,
// hkdf.go) to decrypt an encrypted offline file. Seal is kept for symmetry
// and test-fixture generation even though this SDK is a checkout
// *consumer*, not a producer, of these files.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section E; tests will cover round-trip
// seal/open and tampered-tag rejection (internal/crypto/aesgcm_test.go).
package crypto
