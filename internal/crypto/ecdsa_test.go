package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func genECDSAKeypair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	return priv
}

func TestVerifyECDSA_AcceptsValidASN1Signature(t *testing.T) {
	priv := genECDSAKeypair(t)
	message := []byte("data")
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1() error = %v", err)
	}
	if !VerifyECDSA(&priv.PublicKey, message, sig) {
		t.Fatal("VerifyECDSA() = false, want true")
	}
}

func TestVerifyECDSA_RejectsTamperedMessage(t *testing.T) {
	priv := genECDSAKeypair(t)
	digest := sha256.Sum256([]byte("original"))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1() error = %v", err)
	}
	if VerifyECDSA(&priv.PublicKey, []byte("tampered"), sig) {
		t.Fatal("VerifyECDSA() = true, want false for a tampered message")
	}
}

func TestVerifyECDSA_RejectsWrongKey(t *testing.T) {
	privA := genECDSAKeypair(t)
	privB := genECDSAKeypair(t)
	message := []byte("data")
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, privA, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1() error = %v", err)
	}
	if VerifyECDSA(&privB.PublicKey, message, sig) {
		t.Fatal("VerifyECDSA() = true, want false for a signature from a different key")
	}
}

func TestVerifyECDSA_RejectsMalformedSignatureBytes(t *testing.T) {
	priv := genECDSAKeypair(t)
	if VerifyECDSA(&priv.PublicKey, []byte("data"), []byte("not-asn1-der")) {
		t.Fatal("VerifyECDSA() = true, want false for malformed (non-ASN.1) signature bytes")
	}
}

// TestVerifyECDSA_RejectsRawRSConcatenatedSignature proves this wrapper
// expects ASN.1 DER encoding, not the raw r‖s (64-byte, for P-256)
// concatenated form some other ECDSA wire formats use — documented in
// ecdsa.go's doc comment as the wire-format gotcha for this scheme.
func TestVerifyECDSA_RejectsRawRSConcatenatedSignature(t *testing.T) {
	priv := genECDSAKeypair(t)
	message := []byte("data")
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:]) //nolint:staticcheck // SA1019: intentionally using the raw r,s form to build a non-ASN.1 wire signature for this negative test
	if err != nil {
		t.Fatalf("ecdsa.Sign() error = %v", err)
	}
	rawRS := append(r.Bytes(), s.Bytes()...)
	if VerifyECDSA(&priv.PublicKey, message, rawRS) {
		t.Fatal("VerifyECDSA() accepted a raw r‖s signature, want rejection (ASN.1 DER only)")
	}
}
