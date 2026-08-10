package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAESGCM_RoundTripsAKnownPlaintext(t *testing.T) {
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	plaintext := []byte("license payload json")

	sealed, err := SealAESGCM(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("SealAESGCM() error = %v", err)
	}
	decrypted, err := OpenAESGCM(key, nonce, sealed)
	if err != nil {
		t.Fatalf("OpenAESGCM() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCM_RejectsTamperedTag(t *testing.T) {
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	sealed, err := SealAESGCM(key, nonce, []byte("payload"))
	if err != nil {
		t.Fatalf("SealAESGCM() error = %v", err)
	}
	sealed[len(sealed)-1] ^= 0xff // flip a byte inside the AEAD tag
	if _, err := OpenAESGCM(key, nonce, sealed); err == nil {
		t.Fatal("OpenAESGCM() succeeded against a tampered tag, want an error")
	}
}

func TestAESGCM_RejectsWrongKey(t *testing.T) {
	var key, wrongKey [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	copy(wrongKey[:], "fedcba9876543210fedcba9876543210")
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	sealed, err := SealAESGCM(key, nonce, []byte("payload"))
	if err != nil {
		t.Fatalf("SealAESGCM() error = %v", err)
	}
	if _, err := OpenAESGCM(wrongKey, nonce, sealed); err == nil {
		t.Fatal("OpenAESGCM() succeeded with the wrong key, want an error")
	}
}

func TestAESGCM_RejectsWrongNonceLength(t *testing.T) {
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	if _, err := SealAESGCM(key, []byte("short"), []byte("payload")); err == nil {
		t.Fatal("SealAESGCM() succeeded with a short nonce, want an error")
	}
	if _, err := OpenAESGCM(key, []byte("short"), []byte("ciphertext-and-tag-stub-bytes!!")); err == nil {
		t.Fatal("OpenAESGCM() succeeded with a short nonce, want an error")
	}
}
