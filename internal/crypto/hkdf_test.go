package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestDeriveMachineFileKey_SameInputsProduceSameKey(t *testing.T) {
	a, err := DeriveMachineFileKey("lk", "fp")
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	b, err := DeriveMachineFileKey("lk", "fp")
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	if a != b {
		t.Fatalf("a = %x, b = %x, want equal (reproducible for fixed inputs)", a, b)
	}
}

func TestDeriveMachineFileKey_DifferentLicenseKeyProducesDifferentKey(t *testing.T) {
	a, err := DeriveMachineFileKey("key-a", "fp")
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	b, err := DeriveMachineFileKey("key-b", "fp")
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	if a == b {
		t.Fatal("different license keys produced the same derived key")
	}
}

func TestDeriveMachineFileKey_DifferentFingerprintProducesDifferentKey(t *testing.T) {
	a, err := DeriveMachineFileKey("lk", "fp-a")
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	b, err := DeriveMachineFileKey("lk", "fp-b")
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	if a == b {
		t.Fatal("different fingerprints produced the same derived key")
	}
}

// TestDeriveMachineFileKey_PrefixCollisionInputsProduceDifferentKeys
// proves HKDF binds license key and fingerprint independently via the
// info parameter rather than via naive concatenation: "ab"+"cdef" and
// "abc"+"def" concatenate to the same bytes ("abcdef"), but must not
// derive the same key — matching the server's own test of this property.
func TestDeriveMachineFileKey_PrefixCollisionInputsProduceDifferentKeys(t *testing.T) {
	a, err := DeriveMachineFileKey("ab", "cdef")
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	b, err := DeriveMachineFileKey("abc", "def")
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	if a == b {
		t.Fatal("prefix-collision inputs produced the same derived key — HKDF must prevent this")
	}
}

// TestDeriveMachineFileKey_RFC5869StyleVector exercises the underlying
// golang.org/x/crypto/hkdf primitive directly against RFC 5869 §A.1 (Test
// Case 1: SHA-256, 22-byte IKM, 13-byte salt, 10-byte info, 42-byte OKM),
// confirming this module's HKDF dependency itself produces the
// standard-compliant output our DeriveMachineFileKey wrapper builds on.
func TestDeriveMachineFileKey_RFC5869StyleVector(t *testing.T) {
	ikm := mustHexDecode(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHexDecode(t, "000102030405060708090a0b0c")
	info := mustHexDecode(t, "f0f1f2f3f4f5f6f7f8f9")
	wantOKM := mustHexDecode(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	reader := hkdf.New(sha256.New, ikm, salt, info)
	got := make([]byte, len(wantOKM))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read OKM: %v", err)
	}
	if string(got) != string(wantOKM) {
		t.Fatalf("OKM = %x, want %x", got, wantOKM)
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", s, err)
	}
	return b
}
