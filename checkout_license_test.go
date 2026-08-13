package tamga

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	internalcrypto "github.com/tamga-sh/tamga-go/v2/internal/crypto"
)

// testEd25519Keypair generates a fresh Ed25519 keypair for a single test —
// deliberately not reading testdata/ed25519_test_keypair.json's *private*
// material (that file intentionally records only the public key + seed
// hex for provenance/documentation; tests that need to sign derive their
// own keypair so no single hardcoded private key needs to be trusted
// across the whole suite).
func testEd25519Keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return pub, priv
}

func representativeLicensePayloadJSON() string {
	return `{"data":{"id":"lic-id","type":"licenses","attributes":{"name":"Acme Corp","key":"lic-abc123","status":"ACTIVE","expiry":null,"suspended":false,"protected":false,"uses":0,"scheme":null,"encrypted":false,"strict":false,"floating":false,"max_machines":null,"max_uses":null,"max_users":null,"last_validated_at":null,"last_check_in_at":null,"last_check_out_at":null,"machines_count":0,"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}},"meta":{"iat":1767225600,"jti":"test-jti","kid":"test-kid"}}`
}

// buildLicensePEM builds a .lic PEM exactly the way the real server does
// (docs/sdk.md §4): sign over enc's base64 STRING bytes, never its decoded
// bytes. signOverDecodedBytes, when true, deliberately reproduces the
// central bug this section guards against, for the regression test below.
func buildLicensePEM(t *testing.T, payloadJSON string, priv ed25519.PrivateKey, encryptKey *[32]byte, signOverDecodedBytes bool) string {
	t.Helper()
	var enc, alg string
	if encryptKey == nil {
		enc = base64.StdEncoding.EncodeToString([]byte(payloadJSON))
		alg = AlgBase64Ed25519
	} else {
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
		ciphertextAndTag := gcm.Seal(nil, nonce, []byte(payloadJSON), nil)
		encBytes := append(append([]byte{}, nonce...), ciphertextAndTag...)
		enc = base64.StdEncoding.EncodeToString(encBytes)
		alg = AlgAES256GCMEd25519
	}

	var sigMessage []byte
	if signOverDecodedBytes {
		decoded, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			t.Fatalf("decode enc: %v", err)
		}
		sigMessage = decoded
	} else {
		sigMessage = []byte(enc)
	}
	sig := ed25519.Sign(priv, sigMessage)

	cert := certPayload{Enc: enc, Sig: base64.StdEncoding.EncodeToString(sig), Alg: alg}
	certJSON, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("json.Marshal(cert) error = %v", err)
	}
	body := base64.StdEncoding.EncodeToString(certJSON)
	return licenseFilePEMHeader + "\n" + body + "\n" + licenseFilePEMFooter
}

func TestParseLicenseFile_WellFormedPEMFixtureEndToEnd(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/license_file_plain.lic")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	file, err := ParseLicenseFile(string(pemBytes))
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	if file.Alg != AlgBase64Ed25519 {
		t.Errorf("Alg = %q, want %q", file.Alg, AlgBase64Ed25519)
	}
	if file.Enc == "" || file.Sig == "" {
		t.Errorf("Enc/Sig unexpectedly empty: %+v", file)
	}
}

func TestParseLicenseFile_RejectsMalformedPEM(t *testing.T) {
	if _, err := ParseLicenseFile("not a pem at all"); err == nil {
		t.Fatal("expected an error for a malformed PEM, got nil")
	}
}

func TestLicenseFileVerify_SucceedsAgainstKnownGoodFixture(t *testing.T) {
	pub, priv := testEd25519Keypair(t)
	pem := buildLicensePEM(t, representativeLicensePayloadJSON(), priv, nil, false)
	file, err := ParseLicenseFile(pem)
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	payload, err := file.Verify(pub, "")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if payload.Data.Attributes.Key == nil || *payload.Data.Attributes.Key != "lic-abc123" {
		t.Errorf("payload.Data.Attributes.Key = %v", payload.Data.Attributes.Key)
	}
}

// TestLicenseFileVerify_RejectsDecodedBytesSignature is the regression
// guard for this section's central gotcha: a signature computed over enc's
// DECODED bytes (the wrong way) must NOT verify against this SDK's
// Verify(), which always checks the base64 STRING bytes (the right way).
// A green suite missing this test would not actually prove the verifier
// correct — a self-authored fixture repeating the same bug as the
// implementation would pass a naive round-trip test while silently
// accepting a forged/mismatched real-world file.
func TestLicenseFileVerify_RejectsDecodedBytesSignature(t *testing.T) {
	pub, priv := testEd25519Keypair(t)
	pem := buildLicensePEM(t, representativeLicensePayloadJSON(), priv, nil, true /* sign over decoded bytes — the bug */)
	file, err := ParseLicenseFile(pem)
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	_, err = file.Verify(pub, "")
	if err == nil {
		t.Fatal("Verify() succeeded against a signature computed over decoded bytes, want a rejection")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

// TestVerifyEd25519DirectlyProvesStringVsDecodedBytesGotcha is a narrower,
// primitive-level version of the same regression guard, operating directly
// on internal/crypto's wrapper rather than going through the full
// LicenseFile.Verify pipeline.
func TestVerifyEd25519DirectlyProvesStringVsDecodedBytesGotcha(t *testing.T) {
	pub, priv := testEd25519Keypair(t)
	payload := representativeLicensePayloadJSON()
	enc := base64.StdEncoding.EncodeToString([]byte(payload))
	decodedEncBytes, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("decode enc: %v", err)
	}

	wrongSig := ed25519.Sign(priv, decodedEncBytes) // signs the WRONG thing
	if internalcrypto.VerifyEd25519(pub, []byte(enc), wrongSig) {
		t.Fatal("a signature over decoded bytes must not verify against the base64 string bytes")
	}

	rightSig := ed25519.Sign(priv, []byte(enc)) // signs the RIGHT thing
	if !internalcrypto.VerifyEd25519(pub, []byte(enc), rightSig) {
		t.Fatal("a signature over the base64 string bytes must verify")
	}
}

func TestLicenseFileVerify_EncryptedVariantAcrossLicenseKeyLengths(t *testing.T) {
	tests := []struct {
		name       string
		licenseKey string
	}{
		{"under_32_bytes", "short-key"},
		{"exactly_32_bytes", strings.Repeat("k", 32)},
		{"over_32_bytes", strings.Repeat("k", 50)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv := testEd25519Keypair(t)
			key, _ := internalcrypto.DeriveLicenseFileKey(tt.licenseKey)
			pem := buildLicensePEM(t, representativeLicensePayloadJSON(), priv, &key, false)
			file, err := ParseLicenseFile(pem)
			if err != nil {
				t.Fatalf("ParseLicenseFile() error = %v", err)
			}
			payload, err := file.Verify(pub, tt.licenseKey)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if payload.Data.Attributes.Key == nil || *payload.Data.Attributes.Key != "lic-abc123" {
				t.Errorf("payload.Data.Attributes.Key = %v", payload.Data.Attributes.Key)
			}
		})
	}
}

func TestLicenseFileVerify_EncryptedFixtureFromTestdata(t *testing.T) {
	kpBytes, err := os.ReadFile("testdata/ed25519_test_keypair.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var kp struct {
		PublicKey string `json:"public_key"`
	}
	if unmarshalErr := json.Unmarshal(kpBytes, &kp); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", unmarshalErr)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(kp.PublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}

	pemBytes, err := os.ReadFile("testdata/license_file_encrypted.lic")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	file, err := ParseLicenseFile(string(pemBytes))
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	payload, err := file.Verify(ed25519.PublicKey(pubBytes), "lic-abc123")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if payload.Data.Attributes.Key == nil || *payload.Data.Attributes.Key != "lic-abc123" {
		t.Errorf("payload.Data.Attributes.Key = %v", payload.Data.Attributes.Key)
	}
}

func TestLicenseFileVerify_RejectsTamperedSignature(t *testing.T) {
	pub, priv := testEd25519Keypair(t)
	pem := buildLicensePEM(t, representativeLicensePayloadJSON(), priv, nil, false)
	file, err := ParseLicenseFile(pem)
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}

	// Corrupt the sig field specifically (not a random byte in the whole
	// PEM blob, which could just as easily land in enc/alg or the outer
	// base64/JSON envelope and produce a parse error instead of exercising
	// Verify's signature check) — flip its last base64 character.
	sigBytes := []byte(file.Sig)
	last := len(sigBytes) - 1
	if sigBytes[last] == 'A' {
		sigBytes[last] = 'B'
	} else {
		sigBytes[last] = 'A'
	}
	file.Sig = string(sigBytes)

	if _, err := file.Verify(pub, ""); err == nil {
		t.Fatal("Verify() succeeded against a tampered signature, want an error")
	}
}

func TestLicenseFileVerify_RejectsTamperedCiphertext(t *testing.T) {
	pub, priv := testEd25519Keypair(t)
	licenseKey := "lic-abc123"
	key, _ := internalcrypto.DeriveLicenseFileKey(licenseKey)

	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}
	ciphertextAndTag := gcm.Seal(nil, nonce, []byte(representativeLicensePayloadJSON()), nil)
	encBytes := append(append([]byte{}, nonce...), ciphertextAndTag...)
	encBytes[len(encBytes)-1] ^= 0xff // tamper the AEAD tag

	enc := base64.StdEncoding.EncodeToString(encBytes)
	sig := ed25519.Sign(priv, []byte(enc)) // re-sign over the tampered enc so signature verification passes
	cert := certPayload{Enc: enc, Sig: base64.StdEncoding.EncodeToString(sig), Alg: AlgAES256GCMEd25519}
	certJSON, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	pem := licenseFilePEMHeader + "\n" + base64.StdEncoding.EncodeToString(certJSON) + "\n" + licenseFilePEMFooter

	file, err := ParseLicenseFile(pem)
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	if _, err := file.Verify(pub, licenseKey); err == nil {
		t.Fatal("Verify() succeeded against a tampered AEAD tag, want an error (signature passed, decryption must still fail)")
	}
}

func TestLicenseFileVerify_MissingLicenseKeyForEncryptedFile(t *testing.T) {
	pub, priv := testEd25519Keypair(t)
	key, _ := internalcrypto.DeriveLicenseFileKey("lic-abc123")
	pem := buildLicensePEM(t, representativeLicensePayloadJSON(), priv, &key, false)
	file, err := ParseLicenseFile(pem)
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	_, err = file.Verify(pub, "")
	if !errors.Is(err, ErrLicenseKeyRequired) {
		t.Fatalf("err = %v, want ErrLicenseKeyRequired", err)
	}
}

func TestCheckOutLicense_GETVariantReturnsRawPEM(t *testing.T) {
	var gotPath, gotQuery string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/octet-stream")
		fixture, err := os.ReadFile("testdata/license_file_plain.lic")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		_, _ = w.Write(fixture)
	})
	defer closeFn()

	ttl := 3600
	file, err := c.CheckOutLicense(context.Background(), "lic-id", CheckOutOptions{Encrypt: false, TTL: &ttl})
	if err != nil {
		t.Fatalf("CheckOutLicense() error = %v", err)
	}
	if !strings.Contains(gotPath, "/licenses/lic-id/actions/check-out") {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotQuery, "encrypt=false") || !strings.Contains(gotQuery, "ttl=3600") {
		t.Errorf("query = %q", gotQuery)
	}
	if file.Alg != AlgBase64Ed25519 {
		t.Errorf("Alg = %q", file.Alg)
	}
}

func TestCheckOutLicense_POSTVariantReturnsLicenseFilesResource(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		pemBytes, err := os.ReadFile("testdata/license_file_plain.lic")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		resp := fmt.Sprintf(`{"data":{"id":"cert-id","type":"license-files","attributes":{"certificate":%q,"algorithm":"base64+ed25519+v2","includes":[],"ttl":3600,"expiry":"2026-02-01T00:00:00Z","issued":"2026-01-01T00:00:00Z"}}}`, string(pemBytes))
		_, _ = w.Write([]byte(resp))
	})
	defer closeFn()

	ttl := 3600
	file, err := c.CheckOutLicense(context.Background(), "lic-id", CheckOutOptions{Encrypt: true, TTL: &ttl, UsePOST: true})
	if err != nil {
		t.Fatalf("CheckOutLicense() error = %v", err)
	}
	if file.ID != "cert-id" || file.TTL == nil || *file.TTL != 3600 {
		t.Errorf("file = %+v", file)
	}
	if len(file.Includes) != 0 {
		t.Errorf("Includes = %v, want empty (server always returns [])", file.Includes)
	}
	meta := gotBody["meta"].(map[string]any)
	if meta["encrypt"] != true || meta["ttl"].(float64) != 3600 {
		t.Errorf("request meta = %+v", meta)
	}
}

func TestCheckOutLicense_LicenseNotEncryptedMapping(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"422","code":"LICENSE_NOT_ENCRYPTED","title":"Unprocessable Entity","detail":"license has no key set"}]}`))
	})
	defer closeFn()

	_, err := c.CheckOutLicense(context.Background(), "lic-id", CheckOutOptions{Encrypt: true, UsePOST: true})
	if !errors.Is(err, ErrLicenseNotEncrypted) {
		t.Fatalf("errors.Is(err, ErrLicenseNotEncrypted) = false, err = %v", err)
	}
}

// ExampleLicenseFile_Verify demonstrates parsing and verifying an offline
// .lic file entirely offline, once the account's Ed25519 public key is
// embedded in the calling application. See
// examples/checkout_license/main.go for a full runnable program that
// downloads the file over the network first.
func ExampleLicenseFile_Verify() {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// A real application embeds pub (the account's public key) and
	// receives pem from CheckOutLicense — built by hand here so this
	// example has no network dependency.
	pem := buildExamplePEM(priv)

	file, err := ParseLicenseFile(pem)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	payload, err := file.Verify(pub, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("verified license key:", *payload.Data.Attributes.Key)
	// Output: verified license key: lic-abc123
}

// buildExamplePEM builds a plain (unencrypted) .lic PEM signed by priv, for
// ExampleLicenseFile_Verify's offline-only demonstration.
func buildExamplePEM(priv ed25519.PrivateKey) string {
	enc := base64.StdEncoding.EncodeToString([]byte(representativeLicensePayloadJSON()))
	sig := ed25519.Sign(priv, []byte(enc))
	cert := certPayload{Enc: enc, Sig: base64.StdEncoding.EncodeToString(sig), Alg: AlgBase64Ed25519}
	certJSON, err := json.Marshal(cert)
	if err != nil {
		panic(err)
	}
	body := base64.StdEncoding.EncodeToString(certJSON)
	return licenseFilePEMHeader + "\n" + body + "\n" + licenseFilePEMFooter
}
