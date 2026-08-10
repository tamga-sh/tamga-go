package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func genRSAKeypair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return priv
}

func TestVerifyRSAPKCS1v15_AcceptsValidSignature(t *testing.T) {
	priv := genRSAKeypair(t)
	message := []byte("data")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	if err := VerifyRSAPKCS1v15(&priv.PublicKey, message, sig); err != nil {
		t.Fatalf("VerifyRSAPKCS1v15() error = %v", err)
	}
}

func TestVerifyRSAPKCS1v15_RejectsTamperedMessage(t *testing.T) {
	priv := genRSAKeypair(t)
	digest := sha256.Sum256([]byte("original"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	if err := VerifyRSAPKCS1v15(&priv.PublicKey, []byte("tampered"), sig); err == nil {
		t.Fatal("VerifyRSAPKCS1v15() succeeded against a tampered message, want an error")
	}
}

func TestVerifyRSAPSS_AcceptsValidSignature(t *testing.T) {
	priv := genRSAKeypair(t)
	message := []byte("data")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("rsa.SignPSS() error = %v", err)
	}
	if err := VerifyRSAPSS(&priv.PublicKey, message, sig); err != nil {
		t.Fatalf("VerifyRSAPSS() error = %v", err)
	}
}

func TestVerifyRSAPSS_RejectsTamperedMessage(t *testing.T) {
	priv := genRSAKeypair(t)
	digest := sha256.Sum256([]byte("original"))
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("rsa.SignPSS() error = %v", err)
	}
	if err := VerifyRSAPSS(&priv.PublicKey, []byte("tampered"), sig); err == nil {
		t.Fatal("VerifyRSAPSS() succeeded against a tampered message, want an error")
	}
}

// TestVerifyRSAPKCS1v15_DoesNotAcceptAPSSSignature and its mirror below
// are algorithm-confusion checks: a signature produced under one RSA
// scheme must not verify under the other, even for the same key/message.
func TestVerifyRSAPKCS1v15_DoesNotAcceptAPSSSignature(t *testing.T) {
	priv := genRSAKeypair(t)
	message := []byte("data")
	digest := sha256.Sum256(message)
	pssSig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("rsa.SignPSS() error = %v", err)
	}
	if err := VerifyRSAPKCS1v15(&priv.PublicKey, message, pssSig); err == nil {
		t.Fatal("VerifyRSAPKCS1v15() accepted a PSS signature, want rejection")
	}
}

func TestVerifyRSAPSS_DoesNotAcceptAPKCS1v15Signature(t *testing.T) {
	priv := genRSAKeypair(t)
	message := []byte("data")
	digest := sha256.Sum256(message)
	pkcs1Sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	if err := VerifyRSAPSS(&priv.PublicKey, message, pkcs1Sig); err == nil {
		t.Fatal("VerifyRSAPSS() accepted a PKCS1v15 signature, want rejection")
	}
}

func TestVerifyRSAPSS_AcceptsSaltLengthEqualsHashConvention(t *testing.T) {
	// Many non-Go RSA-PSS implementations (aws-lc-rs among them) default
	// to salt length == hash output length rather than Go's own default
	// (rsa.PSSSaltLengthAuto on sign uses len(hash)+2 by default in some
	// versions) — VerifyRSAPSS must accept either since it uses
	// PSSSaltLengthAuto on the verify side, which recovers the salt length
	// from the signature itself.
	priv := genRSAKeypair(t)
	message := []byte("data")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("rsa.SignPSS() error = %v", err)
	}
	if err := VerifyRSAPSS(&priv.PublicKey, message, sig); err != nil {
		t.Fatalf("VerifyRSAPSS() error = %v, want accept (salt-length-equals-hash convention)", err)
	}
}
