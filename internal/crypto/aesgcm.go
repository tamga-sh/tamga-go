// Package crypto — aesgcm.go wraps stdlib crypto/cipher + crypto/aes for
// AES-256-GCM, shared by both the license file (.lic) and machine file
// (.machine) checkout formats. Both derive their 32-byte key with
// HKDF-SHA256 and differ only in the salt/info pair they use (hkdf.go) —
// this file only implements the seal/open primitives themselves,
// key-agnostic.
//
// Wire format for both: nonce(12B) || ciphertext || tag(16B), random nonce
// per checkout call.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// OpenAESGCM decrypts ciphertextAndTag (ciphertext with the 16-byte AEAD
// tag appended, as produced by the server's seal-in-place-append-tag) with
// AES-256-GCM. Returns an error for both a wrong key and a tampered
// ciphertext/tag — AES-GCM deliberately doesn't distinguish the two
// failure modes at the API level, since doing so would leak information
// useful to a chosen-ciphertext attacker.
func OpenAESGCM(key [32]byte, nonce, ciphertextAndTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("tamga: aes-256-gcm: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tamga: aes-256-gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("tamga: aes-256-gcm: invalid nonce length %d, want %d", len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, fmt.Errorf("tamga: aes-256-gcm: decryption failed (wrong key or tampered ciphertext)")
	}
	return plaintext, nil
}

// SealAESGCM encrypts plaintext with AES-256-GCM under the given key and
// nonce, returning ciphertext||tag. Kept for symmetry and test-fixture
// generation even though this SDK is a checkout *consumer*, not a
// *producer*, of encrypted offline files in production use.
func SealAESGCM(key [32]byte, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("tamga: aes-256-gcm: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tamga: aes-256-gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("tamga: aes-256-gcm: invalid nonce length %d, want %d", len(nonce), gcm.NonceSize())
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}
