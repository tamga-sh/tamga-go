package tamga

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"testing"

	internalcrypto "github.com/tamga-sh/tamga-go/internal/crypto"
)

func representativeMachinePayloadJSON() string {
	return `{"data":{"id":"mach-id","type":"machines","attributes":{"fingerprint":"fp-abc123","cores":4,"memory":null,"disk":null,"ip":null,"hostname":"host1","platform":"linux","name":null,"heartbeat_status":"NOT_STARTED","last_heartbeat_at":null,"next_heartbeat_at":null,"last_check_out_at":null,"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`
}

// signForScheme signs enc (the base64 STRING, matching the section's
// shared gotcha) with a freshly generated scheme-appropriate keypair,
// returning the crypto.PublicKey value ready to pass to
// (*MachineFile).Verify, plus the raw signature bytes.
func signForScheme(t *testing.T, scheme LicenseScheme, enc string) (any, []byte) {
	t.Helper()
	switch scheme {
	case SchemeEd25519Sign:
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}
		return pub, ed25519.Sign(priv, []byte(enc))
	case SchemeRSA2048PKCS1Sign:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		digest := sha256.Sum256([]byte(enc))
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
		}
		return &priv.PublicKey, sig
	case SchemeRSA2048PKCS1PSSSign:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		digest := sha256.Sum256([]byte(enc))
		sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], nil)
		if err != nil {
			t.Fatalf("rsa.SignPSS() error = %v", err)
		}
		return &priv.PublicKey, sig
	case SchemeECDSAP256Sign:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() error = %v", err)
		}
		digest := sha256.Sum256([]byte(enc))
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatalf("ecdsa.SignASN1() error = %v", err)
		}
		return &priv.PublicKey, sig
	default:
		t.Fatalf("signForScheme: unsupported scheme %v", scheme)
		return nil, nil
	}
}

func schemeAlgSuffixForTest(t *testing.T, scheme LicenseScheme) string {
	t.Helper()
	suffix, err := schemeAlgSuffix(scheme)
	if err != nil {
		t.Fatalf("schemeAlgSuffix() error = %v", err)
	}
	return suffix
}

// buildMachinePEM builds a .machine PEM for the given scheme, optionally
// encrypted (encryptKey != nil).
func buildMachinePEM(t *testing.T, scheme LicenseScheme, encryptKey *[32]byte) (any /* pub */, string /* pem */) {
	t.Helper()
	suffix := schemeAlgSuffixForTest(t, scheme)
	var encPrefix, enc string
	if encryptKey == nil {
		encPrefix = "base64"
		enc = base64.StdEncoding.EncodeToString([]byte(representativeMachinePayloadJSON()))
	} else {
		encPrefix = "aes-256-gcm"
		nonce := make([]byte, 12)
		for i := range nonce {
			nonce[i] = byte(i + 1)
		}
		block, err := aes.NewCipher(encryptKey[:])
		if err != nil {
			t.Fatalf("aes.NewCipher() error = %v", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("cipher.NewGCM() error = %v", err)
		}
		ciphertextAndTag := gcm.Seal(nil, nonce, []byte(representativeMachinePayloadJSON()), nil)
		encBytes := append(append([]byte{}, nonce...), ciphertextAndTag...)
		enc = base64.StdEncoding.EncodeToString(encBytes)
	}

	pub, sig := signForScheme(t, scheme, enc)
	cert := certPayload{Enc: enc, Sig: base64.StdEncoding.EncodeToString(sig), Alg: encPrefix + "+" + suffix}
	certJSON, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	pemBody := base64.StdEncoding.EncodeToString(certJSON)
	pem := machineFilePEMHeader + "\n" + pemBody + "\n" + machineFilePEMFooter
	return pub, pem
}

func TestParseMachineFile_WellFormedPEMFixture(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/machine_file_ed25519.machine")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	file, err := ParseMachineFile(string(pemBytes))
	if err != nil {
		t.Fatalf("ParseMachineFile() error = %v", err)
	}
	if file.Alg != "base64+ed25519" {
		t.Errorf("Alg = %q", file.Alg)
	}
}

func TestMachineFileVerify_EachScheme(t *testing.T) {
	schemes := []LicenseScheme{SchemeEd25519Sign, SchemeRSA2048PKCS1Sign, SchemeRSA2048PKCS1PSSSign, SchemeECDSAP256Sign}
	for _, scheme := range schemes {
		t.Run(string(scheme), func(t *testing.T) {
			pub, pem := buildMachinePEM(t, scheme, nil)
			file, err := ParseMachineFile(pem)
			if err != nil {
				t.Fatalf("ParseMachineFile() error = %v", err)
			}
			payload, err := file.Verify(scheme, pub, "", "")
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if payload.Data.Attributes.Fingerprint != "fp-abc123" {
				t.Errorf("Fingerprint = %q", payload.Data.Attributes.Fingerprint)
			}
		})
	}
}

func TestMachineFileVerify_FixturesFromTestdata(t *testing.T) {
	keysBytes, err := os.ReadFile("testdata/machine_test_keys.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var keys struct {
		Ed25519 struct {
			PublicKeyBase64Raw32 string `json:"public_key_base64_raw32"`
		} `json:"ed25519"`
		RSAPKCS1 struct {
			PublicKeyBase64SPKIDER string `json:"public_key_base64_spki_der"`
		} `json:"rsa_pkcs1"`
		RSAPSS struct {
			PublicKeyBase64SPKIDER string `json:"public_key_base64_spki_der"`
		} `json:"rsa_pss"`
		ECDSAP256 struct {
			PublicKeyBase64UncompressedPoint65 string `json:"public_key_base64_uncompressed_point65"`
			LicenseKey                         string `json:"license_key"`
			Fingerprint                        string `json:"fingerprint"`
		} `json:"ecdsa_p256"`
	}
	if unmarshalErr := json.Unmarshal(keysBytes, &keys); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", unmarshalErr)
	}

	t.Run("ed25519", func(t *testing.T) {
		pubBytes, err := base64.StdEncoding.DecodeString(keys.Ed25519.PublicKeyBase64Raw32)
		if err != nil {
			t.Fatalf("decode pubkey: %v", err)
		}
		pemBytes, err := os.ReadFile("testdata/machine_file_ed25519.machine")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		file, err := ParseMachineFile(string(pemBytes))
		if err != nil {
			t.Fatalf("ParseMachineFile() error = %v", err)
		}
		payload, err := file.Verify(SchemeEd25519Sign, ed25519.PublicKey(pubBytes), "", "")
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if payload.Data.Attributes.Fingerprint != "fp-abc123" {
			t.Errorf("Fingerprint = %q", payload.Data.Attributes.Fingerprint)
		}
	})

	t.Run("rsa_pkcs1", func(t *testing.T) {
		der, err := base64.StdEncoding.DecodeString(keys.RSAPKCS1.PublicKeyBase64SPKIDER)
		if err != nil {
			t.Fatalf("decode pubkey: %v", err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("ParsePKIXPublicKey() error = %v", err)
		}
		pemBytes, err := os.ReadFile("testdata/machine_file_rsa_pkcs1.machine")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		file, err := ParseMachineFile(string(pemBytes))
		if err != nil {
			t.Fatalf("ParseMachineFile() error = %v", err)
		}
		payload, err := file.Verify(SchemeRSA2048PKCS1Sign, pub, "", "")
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if payload.Data.Attributes.Fingerprint != "fp-abc123" {
			t.Errorf("Fingerprint = %q", payload.Data.Attributes.Fingerprint)
		}
	})

	t.Run("rsa_pss", func(t *testing.T) {
		der, err := base64.StdEncoding.DecodeString(keys.RSAPSS.PublicKeyBase64SPKIDER)
		if err != nil {
			t.Fatalf("decode pubkey: %v", err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("ParsePKIXPublicKey() error = %v", err)
		}
		pemBytes, err := os.ReadFile("testdata/machine_file_rsa_pss.machine")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		file, err := ParseMachineFile(string(pemBytes))
		if err != nil {
			t.Fatalf("ParseMachineFile() error = %v", err)
		}
		payload, err := file.Verify(SchemeRSA2048PKCS1PSSSign, pub, "", "")
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if payload.Data.Attributes.Fingerprint != "fp-abc123" {
			t.Errorf("Fingerprint = %q", payload.Data.Attributes.Fingerprint)
		}
	})

	t.Run("ecdsa_encrypted", func(t *testing.T) {
		pointBytes, err := base64.StdEncoding.DecodeString(keys.ECDSAP256.PublicKeyBase64UncompressedPoint65)
		if err != nil {
			t.Fatalf("decode pubkey: %v", err)
		}
		if len(pointBytes) != 65 || pointBytes[0] != 0x04 {
			t.Fatalf("unexpected point encoding, len=%d prefix=%x", len(pointBytes), pointBytes[0])
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(pointBytes[1:33]),
			Y:     new(big.Int).SetBytes(pointBytes[33:65]),
		}

		pemBytes, err := os.ReadFile("testdata/machine_file_ecdsa.machine")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		file, err := ParseMachineFile(string(pemBytes))
		if err != nil {
			t.Fatalf("ParseMachineFile() error = %v", err)
		}
		payload, err := file.Verify(SchemeECDSAP256Sign, pub, keys.ECDSAP256.LicenseKey, keys.ECDSAP256.Fingerprint)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if payload.Data.Attributes.Fingerprint != "fp-abc123" {
			t.Errorf("Fingerprint = %q", payload.Data.Attributes.Fingerprint)
		}
	})
}

// TestMachineFileVerify_RejectsJWTSchemeBeforeAnyCryptoPrimitive is the
// regression guard for this section's rejected-scheme gotcha: verify a
// file that would otherwise validate correctly under some other scheme,
// but ask Verify to treat it as SchemeRSA2048JWTRS256 — it must reject
// immediately with ErrSchemeNotSupported, never attempt (or fail
// differently inside) any signature check.
func TestMachineFileVerify_RejectsJWTSchemeBeforeAnyCryptoPrimitive(t *testing.T) {
	pub, pem := buildMachinePEM(t, SchemeEd25519Sign, nil)
	file, err := ParseMachineFile(pem)
	if err != nil {
		t.Fatalf("ParseMachineFile() error = %v", err)
	}
	_, err = file.Verify(SchemeRSA2048JWTRS256, pub, "", "")
	if !errors.Is(err, ErrSchemeNotSupported) {
		t.Fatalf("err = %v, want ErrSchemeNotSupported", err)
	}
}

func TestCheckTTL_BoundaryValues(t *testing.T) {
	tests := []struct {
		name    string
		ttl     int
		wantErr bool
	}{
		{"zero", 0, true},
		{"one", 1, false},
		{"max", maxCheckoutTTLSeconds, false},
		{"max_plus_one", maxCheckoutTTLSeconds + 1, true},
		{"negative", -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkTTL(tt.ttl)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkTTL(%d) error = %v, wantErr %v", tt.ttl, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrTTLInvalid) {
				t.Errorf("checkTTL(%d) error = %v, want it to match ErrTTLInvalid", tt.ttl, err)
			}
		})
	}
}

func TestCheckOutMachine_RejectsInvalidTTLBeforeRequest(t *testing.T) {
	var serverCalled bool
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusOK)
	})
	defer closeFn()

	badTTL := 0
	_, err := c.CheckOutMachine(context.Background(), "mach-id", CheckOutOptions{TTL: &badTTL})
	if !errors.Is(err, ErrTTLInvalid) {
		t.Fatalf("err = %v, want ErrTTLInvalid", err)
	}
	if serverCalled {
		t.Fatal("server was called despite an invalid TTL — must short-circuit client-side")
	}
}

// TestMachineFileVerify_EncryptedRequiresCorrectFingerprint proves wrong
// fingerprint fails decryption via an AEAD tag mismatch, not a silent
// garbage decrypt.
func TestMachineFileVerify_EncryptedRequiresCorrectFingerprint(t *testing.T) {
	licenseKey := "lic-abc123"
	fingerprint := "fp-abc123"
	key, err := internalcrypto.DeriveMachineFileKey(licenseKey, fingerprint)
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	pub, pem := buildMachinePEM(t, SchemeEd25519Sign, &key)
	file, err := ParseMachineFile(pem)
	if err != nil {
		t.Fatalf("ParseMachineFile() error = %v", err)
	}

	// Correct fingerprint decrypts fine.
	payload, err := file.Verify(SchemeEd25519Sign, pub, licenseKey, fingerprint)
	if err != nil {
		t.Fatalf("Verify() with correct fingerprint error = %v", err)
	}
	if payload.Data.Attributes.Fingerprint != "fp-abc123" {
		t.Errorf("Fingerprint = %q", payload.Data.Attributes.Fingerprint)
	}

	// Wrong fingerprint fails cleanly (wrong derived key -> AEAD tag
	// mismatch), not a panic or silent corruption.
	_, err = file.Verify(SchemeEd25519Sign, pub, licenseKey, "wrong-fingerprint")
	if err == nil {
		t.Fatal("Verify() succeeded with the wrong fingerprint, want an error")
	}
}

func TestMachineFileVerify_MissingLicenseKeyAndFingerprint(t *testing.T) {
	licenseKey := "lic-abc123"
	fingerprint := "fp-abc123"
	key, err := internalcrypto.DeriveMachineFileKey(licenseKey, fingerprint)
	if err != nil {
		t.Fatalf("DeriveMachineFileKey() error = %v", err)
	}
	pub, pem := buildMachinePEM(t, SchemeEd25519Sign, &key)
	file, err := ParseMachineFile(pem)
	if err != nil {
		t.Fatalf("ParseMachineFile() error = %v", err)
	}

	_, err = file.Verify(SchemeEd25519Sign, pub, "", fingerprint)
	if !errors.Is(err, ErrLicenseKeyRequired) {
		t.Fatalf("err = %v, want ErrLicenseKeyRequired", err)
	}

	_, err = file.Verify(SchemeEd25519Sign, pub, licenseKey, "")
	if !errors.Is(err, ErrFingerprintRequired) {
		t.Fatalf("err = %v, want ErrFingerprintRequired", err)
	}
}

func TestMachineFileVerify_AlgSuffixMismatchRejected(t *testing.T) {
	// File genuinely signed+verifiable under Ed25519, but caller claims
	// RSA-PKCS1 — the alg-suffix cross-check must catch this before any
	// RSA verification is even attempted.
	pub, pem := buildMachinePEM(t, SchemeEd25519Sign, nil)
	file, err := ParseMachineFile(pem)
	if err != nil {
		t.Fatalf("ParseMachineFile() error = %v", err)
	}
	_, err = file.Verify(SchemeRSA2048PKCS1Sign, pub, "", "")
	if err == nil {
		t.Fatal("Verify() succeeded despite an alg-suffix/scheme mismatch, want an error")
	}
}

func TestCheckOutMachine_SchemeNotSupportedMapping(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"422","code":"SCHEME_NOT_SUPPORTED","title":"Unprocessable Entity","detail":"scheme not supported"}]}`))
	})
	defer closeFn()

	_, err := c.CheckOutMachine(context.Background(), "mach-id", CheckOutOptions{UsePOST: true})
	if !errors.Is(err, ErrSchemeNotSupported) {
		t.Fatalf("errors.Is(err, ErrSchemeNotSupported) = false, err = %v", err)
	}
}

func TestCheckOutMachine_GETVariantReturnsRawPEM(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		fixture, err := os.ReadFile("testdata/machine_file_ed25519.machine")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		_, _ = w.Write(fixture)
	})
	defer closeFn()

	file, err := c.CheckOutMachine(context.Background(), "mach-id", CheckOutOptions{})
	if err != nil {
		t.Fatalf("CheckOutMachine() error = %v", err)
	}
	if file.Alg != "base64+ed25519" {
		t.Errorf("Alg = %q", file.Alg)
	}
}

func TestCheckOutMachine_POSTVariantReturnsMachineFilesResource(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		pemBytes, err := os.ReadFile("testdata/machine_file_ed25519.machine")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		resp := fmt.Sprintf(`{"data":{"id":"cert-id","type":"machine-files","attributes":{"certificate":%q,"algorithm":"base64+ed25519","includes":[],"ttl":null,"expiry":null,"issued":"2026-01-01T00:00:00Z"}}}`, string(pemBytes))
		_, _ = w.Write([]byte(resp))
	})
	defer closeFn()

	file, err := c.CheckOutMachine(context.Background(), "mach-id", CheckOutOptions{UsePOST: true})
	if err != nil {
		t.Fatalf("CheckOutMachine() error = %v", err)
	}
	if file.ID != "cert-id" {
		t.Errorf("ID = %q", file.ID)
	}
}
