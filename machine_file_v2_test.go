package tamga

// machine_file_v2_test.go is the machine-file v2 wire-format conformance
// suite, and it is deliberately the ONLY place in this repo that asserts a
// .machine file verifies.
//
// Every file under testdata/server-machine-file-fixtures/ came out of the
// tamga-api server's own encode_machine_file — none of them was produced by
// this SDK, or by a Go reimplementation of the format. That is the whole
// point. The three defects this suite pins (an alg suffix compared against
// the wrong half of the string, an encrypted enc decoded as one base64 blob
// instead of two dot-separated halves, and a signed exp that was never
// enforced) survived for two years precisely because every SDK tested itself
// against a fixture it generated from its own misreading: CI stayed green
// while nothing the server actually emitted could be opened.
//
// The suite iterates manifest.json rather than naming fixtures, so a fixture
// added to that directory is covered with no edit here. Adding a fixture this
// SDK generated itself would defeat the exercise; if a case is missing, get it
// from the server's encoder.
//
// Clock handling: the "valid" fixtures carry a real exp an hour after they
// were minted, so they go stale on the wall clock. Tests therefore drive
// (*MachineFile).Now explicitly — epoch 0 to take the expiry check out of
// play while checking signature/decrypt/parse, and an exp-relative timestamp
// when the expiry check itself is what is under test. That override is the
// same trusted-timestamp escape hatch (*LicenseFile).Now provides, and it
// exists for the same reason: offline, the local clock is the attacker's.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const serverMachineFixtureDir = "testdata/server-machine-file-fixtures"

// serverMachineFixture is one manifest.json entry. The manifest is written by
// the fixture generator alongside the certificates; the fields mirror what the
// server knew when it signed each file.
type serverMachineFixture struct {
	LicenseKey *string `json:"license_key"`

	Name string `json:"-"`

	File         string `json:"file"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
	KID          string `json:"kid"`
	Fingerprint  string `json:"fingerprint"`
	Scheme       string `json:"scheme"`

	Encrypted         bool `json:"encrypted"`
	EncIsDotSeparated bool `json:"enc_is_dot_separated"`
	Expired           bool `json:"expired"`
}

// loadServerMachineFixtures reads manifest.json and returns its entries sorted
// by name, so subtests run in a stable order.
func loadServerMachineFixtures(t *testing.T) []serverMachineFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(serverMachineFixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("ReadFile(manifest.json) error = %v", err)
	}
	var byName map[string]serverMachineFixture
	if err := json.Unmarshal(raw, &byName); err != nil {
		t.Fatalf("json.Unmarshal(manifest.json) error = %v", err)
	}
	if len(byName) == 0 {
		t.Fatal("manifest.json declares no fixtures")
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]serverMachineFixture, 0, len(names))
	for _, name := range names {
		fx := byName[name]
		fx.Name = name
		out = append(out, fx)
	}
	return out
}

// scheme maps the manifest's Rust LicenseScheme variant name to this SDK's
// wire-value constant. The manifest names the variant, not the wire value,
// because it is written from the server side.
func (fx serverMachineFixture) scheme(t *testing.T) LicenseScheme {
	t.Helper()
	switch fx.Scheme {
	case "Ed25519Sign":
		return SchemeEd25519Sign
	case "EcdsaP256Sign":
		return SchemeECDSAP256Sign
	case "Rsa2048Pkcs1Sign":
		return SchemeRSA2048PKCS1Sign
	case "Rsa2048Pkcs1PssSign":
		return SchemeRSA2048PKCS1PSSSign
	case "Rsa2048JwtRs256":
		return SchemeRSA2048JWTRS256
	default:
		t.Fatalf("manifest fixture %q declares unknown scheme %q", fx.Name, fx.Scheme)
		return ""
	}
}

// publicKey decodes public_key_b64 into the concrete key type
// (*MachineFile).Verify expects for this fixture's scheme: a raw 32-byte
// Ed25519 key, an uncompressed 65-byte P-256 point, or a PKCS#1 RSAPublicKey
// DER blob.
func (fx serverMachineFixture) publicKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(fx.PublicKeyB64)
	if err != nil {
		t.Fatalf("fixture %q: decode public_key_b64: %v", fx.Name, err)
	}
	switch fx.scheme(t) {
	case SchemeEd25519Sign:
		if len(der) != ed25519.PublicKeySize {
			t.Fatalf("fixture %q: ed25519 public key is %d bytes, want %d", fx.Name, len(der), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(der)
	case SchemeECDSAP256Sign:
		if len(der) != 65 || der[0] != 0x04 {
			t.Fatalf("fixture %q: ecdsa public key is not an uncompressed P-256 point (len=%d prefix=%#x)", fx.Name, len(der), der[0])
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(der[1:33]),
			Y:     new(big.Int).SetBytes(der[33:65]),
		}
	case SchemeRSA2048PKCS1Sign, SchemeRSA2048PKCS1PSSSign:
		// The current fixtures carry a PKCS#1 RSAPublicKey DER (270 bytes
		// for RSA-2048); the server's own key_material.rs documents the
		// published account key as SubjectPublicKeyInfo (294 bytes). Accept
		// either rather than pin one, so a regenerated fixture set in the
		// other encoding does not read as a signature failure here.
		if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
			return pub
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("fixture %q: RSA public key is neither PKCS#1 nor SPKI DER: %v", fx.Name, err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("fixture %q: SPKI DER holds a %T, want *rsa.PublicKey", fx.Name, pub)
		}
		return rsaPub
	default:
		t.Fatalf("fixture %q: no public-key decoder for scheme %q", fx.Name, fx.Scheme)
		return nil
	}
}

// creds returns the (licenseKey, fingerprint) pair Verify needs for this
// fixture — both empty for a plain file, both populated for an encrypted one.
func (fx serverMachineFixture) creds() (licenseKey, fingerprint string) {
	if !fx.Encrypted {
		return "", ""
	}
	if fx.LicenseKey != nil {
		licenseKey = *fx.LicenseKey
	}
	return licenseKey, fx.Fingerprint
}

// parse reads and parses the fixture PEM. It does not verify.
func (fx serverMachineFixture) parse(t *testing.T) *MachineFile {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(serverMachineFixtureDir, fx.File))
	if err != nil {
		t.Fatalf("fixture %q: ReadFile: %v", fx.Name, err)
	}
	file, err := ParseMachineFile(string(pemBytes))
	if err != nil {
		t.Fatalf("fixture %q: ParseMachineFile: %v", fx.Name, err)
	}
	return file
}

// atEpoch pins Verify's clock to the Unix epoch, which is before any exp a
// fixture can carry — the expiry check is then guaranteed not to fire, so a
// failure isolates to signature, decode, decrypt or parse.
func atEpoch() func() int64 { return func() int64 { return 0 } }

func at(ts int64) func() int64 { return func() int64 { return ts } }

// TestServerMachineFixtures_ManifestMatchesFiles guards the fixture set
// itself: if a regenerated fixture stops matching what the manifest says it
// is, every other test in this file is measuring the wrong thing, and the
// failure should say so here rather than surface as a mystery signature
// error.
func TestServerMachineFixtures_ManifestMatchesFiles(t *testing.T) {
	fixtures := loadServerMachineFixtures(t)
	schemesSeen := map[string]bool{}
	var sawEncrypted, sawPlain, sawExpired bool

	for _, fx := range fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			file := fx.parse(t)
			if file.Alg != fx.Alg {
				t.Errorf("Alg = %q, manifest says %q", file.Alg, fx.Alg)
			}
			if !strings.HasSuffix(file.Alg, "+v2") {
				t.Errorf("Alg = %q, every server-issued machine file carries the +v2 marker", file.Alg)
			}
			gotDotSeparated := strings.Contains(file.Enc, ".")
			if gotDotSeparated != fx.EncIsDotSeparated {
				t.Errorf("enc dot-separated = %v, manifest says %v", gotDotSeparated, fx.EncIsDotSeparated)
			}
			if fx.Encrypted != fx.EncIsDotSeparated {
				t.Errorf("manifest disagrees with itself: encrypted=%v but enc_is_dot_separated=%v", fx.Encrypted, fx.EncIsDotSeparated)
			}
			if fx.Encrypted && strings.Count(file.Enc, ".") != 1 {
				t.Errorf("encrypted enc has %d dots, want exactly 1", strings.Count(file.Enc, "."))
			}
		})
		schemesSeen[fx.Scheme] = true
		sawEncrypted = sawEncrypted || fx.Encrypted
		sawPlain = sawPlain || !fx.Encrypted
		sawExpired = sawExpired || fx.Expired
	}

	// Not a hardcoded fixture list — just a floor, so a truncated fixture
	// directory cannot quietly reduce this suite to "ed25519, plain, valid".
	for _, want := range []string{"Ed25519Sign", "EcdsaP256Sign", "Rsa2048Pkcs1Sign", "Rsa2048Pkcs1PssSign"} {
		if !schemesSeen[want] {
			t.Errorf("no fixture for scheme %s", want)
		}
	}
	if !sawEncrypted || !sawPlain || !sawExpired {
		t.Errorf("fixture set is missing a variant: encrypted=%v plain=%v expired=%v", sawEncrypted, sawPlain, sawExpired)
	}
}

// TestMachineFileVerify_ServerFixtures is the headline test: every file the
// server emits must open. Before the M1/M2 fix not one of them did — the alg
// cross-check compared "ed25519+v2" against "ed25519" and rejected the lot,
// and the encrypted ones additionally died in base64 decoding on the "."
// separator.
func TestMachineFileVerify_ServerFixtures(t *testing.T) {
	for _, fx := range loadServerMachineFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			file := fx.parse(t)
			file.Now = atEpoch()
			licenseKey, fingerprint := fx.creds()

			payload, err := file.Verify(fx.scheme(t), fx.publicKey(t), licenseKey, fingerprint)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if payload.Data.Attributes.Fingerprint != fx.Fingerprint {
				t.Errorf("Data.Attributes.Fingerprint = %q, want %q", payload.Data.Attributes.Fingerprint, fx.Fingerprint)
			}
			// M3: the claims exist and are surfaced. kid comes from the
			// manifest, so this is a cross-check against what the server
			// knew, not against the file describing itself.
			if payload.Claims.KeyID != fx.KID {
				t.Errorf("Claims.KeyID = %q, want %q", payload.Claims.KeyID, fx.KID)
			}
			if payload.Claims.IssuedAt == 0 {
				t.Error("Claims.IssuedAt = 0, want the signed iat")
			}
			if payload.Claims.ID == "" {
				t.Error("Claims.ID (jti) is empty, want the signed jti")
			}
		})
	}
}

// TestMachineFileVerify_ServerFixtures_ExpiryEnforced is the M3 regression:
// a machine file's signed exp is enforced, with the same 60-second tolerance
// and the same *ExpiredError the license-file path uses, and an expired file
// is distinguishable from a forged one.
func TestMachineFileVerify_ServerFixtures_ExpiryEnforced(t *testing.T) {
	for _, fx := range loadServerMachineFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			scheme, pub := fx.scheme(t), fx.publicKey(t)
			licenseKey, fingerprint := fx.creds()

			file := fx.parse(t)
			file.Now = atEpoch()
			payload, err := file.Verify(scheme, pub, licenseKey, fingerprint)
			if err != nil {
				t.Fatalf("Verify() at epoch error = %v", err)
			}
			exp := payload.Claims.ExpiresAt
			if exp == 0 {
				// Legitimate: check_out_machine.rs sets exp from
				// ttl.map(..), so a checkout with no ttl produces a file
				// that genuinely never expires. Absence is not an error.
				t.Skip("fixture carries no exp claim (checked out without a ttl)")
			}

			// Exactly at the tolerance edge the file is still good: the
			// comparison is now-TOLERANCE > exp, not >=.
			file = fx.parse(t)
			file.Now = at(exp + clockSkewToleranceSeconds)
			if _, edgeErr := file.Verify(scheme, pub, licenseKey, fingerprint); edgeErr != nil {
				t.Errorf("Verify() at exp+%d error = %v, want success (skew tolerance)", clockSkewToleranceSeconds, edgeErr)
			}

			// One second past it, expired.
			file = fx.parse(t)
			file.Now = at(exp + clockSkewToleranceSeconds + 1)
			_, err = file.Verify(scheme, pub, licenseKey, fingerprint)
			var expired *ExpiredError
			if !errors.As(err, &expired) {
				t.Fatalf("Verify() at exp+%d error = %v, want *ExpiredError", clockSkewToleranceSeconds+1, err)
			}
			if expired.ExpiresAt != exp {
				t.Errorf("ExpiredError.ExpiresAt = %d, want %d", expired.ExpiresAt, exp)
			}
			// "Expired" and "forged" must not collapse into one outcome —
			// a caller that cannot tell them apart either warns about
			// tampering when a trial merely ended, or treats a forgery as
			// a renewal prompt.
			if errors.Is(err, ErrInvalidSignature) {
				t.Error("expiry surfaced as ErrInvalidSignature; callers cannot tell an ended file from a forged one")
			}

			// A fixture the manifest calls expired must also be rejected on
			// the real wall clock, with no injected timestamp at all —
			// its exp is permanently in the past.
			if fx.Expired {
				file = fx.parse(t)
				_, err = file.Verify(scheme, pub, licenseKey, fingerprint)
				if !errors.As(err, &expired) {
					t.Errorf("Verify() on the real clock error = %v, want *ExpiredError", err)
				}
			}
		})
	}
}

// TestMachineFileVerify_ServerFixtures_EncryptedBindsToFingerprint covers the
// M2 decrypt path end to end: the right license key + fingerprint open the
// file, and either one wrong does not. The fingerprint requirement is what
// binds a machine file to one machine — the license key alone must not open
// it anywhere else.
func TestMachineFileVerify_ServerFixtures_EncryptedBindsToFingerprint(t *testing.T) {
	var ran int
	for _, fx := range loadServerMachineFixtures(t) {
		if !fx.Encrypted {
			continue
		}
		ran++
		t.Run(fx.Name, func(t *testing.T) {
			scheme, pub := fx.scheme(t), fx.publicKey(t)
			licenseKey, fingerprint := fx.creds()

			// An encrypted enc is two separately-base64'd halves joined by
			// ".", so decoding it as a single blob — what this SDK did —
			// cannot even get off the ground. Asserted directly so the
			// regression is legible without archaeology.
			file := fx.parse(t)
			if _, err := base64.StdEncoding.DecodeString(file.Enc); err == nil {
				t.Error("encrypted enc decoded as a single base64 blob; the fixture is not in <nonce_b64>.<cipher_b64> form")
			}

			file.Now = atEpoch()
			if _, err := file.Verify(scheme, pub, licenseKey, fingerprint); err != nil {
				t.Fatalf("Verify() with correct credentials error = %v", err)
			}

			file = fx.parse(t)
			file.Now = atEpoch()
			if _, err := file.Verify(scheme, pub, licenseKey, "wrong-fingerprint"); err == nil {
				t.Error("Verify() succeeded with the wrong fingerprint")
			}

			file = fx.parse(t)
			file.Now = atEpoch()
			if _, err := file.Verify(scheme, pub, "WRONG-LICENSE-KEY", fingerprint); err == nil {
				t.Error("Verify() succeeded with the wrong license key")
			}

			file = fx.parse(t)
			file.Now = atEpoch()
			if _, err := file.Verify(scheme, pub, "", fingerprint); !errors.Is(err, ErrLicenseKeyRequired) {
				t.Errorf("Verify() with no license key error = %v, want ErrLicenseKeyRequired", err)
			}

			file = fx.parse(t)
			file.Now = atEpoch()
			if _, err := file.Verify(scheme, pub, licenseKey, ""); !errors.Is(err, ErrFingerprintRequired) {
				t.Errorf("Verify() with no fingerprint error = %v, want ErrFingerprintRequired", err)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no encrypted fixtures in the manifest; the M2 decrypt path is untested")
	}
}

// TestMachineFileVerify_ServerFixtures_TamperedEncFailsSignatureFirst pins the
// fail-closed ordering: the signature covers enc's STRING bytes and is checked
// before enc is decoded, split, decrypted or parsed. A tampered file must come
// back ErrInvalidSignature, never a base64 or AEAD error that would reveal the
// verifier had already started chewing on attacker-controlled bytes.
func TestMachineFileVerify_ServerFixtures_TamperedEncFailsSignatureFirst(t *testing.T) {
	for _, fx := range loadServerMachineFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			scheme, pub := fx.scheme(t), fx.publicKey(t)
			licenseKey, fingerprint := fx.creds()

			// Still-valid base64, different bytes.
			file := fx.parse(t)
			file.Now = atEpoch()
			file.Enc = flipOneBase64Char(t, file.Enc)
			if _, err := file.Verify(scheme, pub, licenseKey, fingerprint); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("Verify() on a byte-flipped enc error = %v, want ErrInvalidSignature", err)
			}

			// Not valid base64 at all: the signature check must still be
			// what rejects it, proving no decode ran first.
			file = fx.parse(t)
			file.Now = atEpoch()
			file.Enc += "!!!not-base64!!!"
			if _, err := file.Verify(scheme, pub, licenseKey, fingerprint); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("Verify() on a non-base64 enc error = %v, want ErrInvalidSignature (decode must not run before verification)", err)
			}
		})
	}
}

// flipOneBase64Char rewrites one character of s to a different base64
// character, keeping the string decodable but changing the signed bytes.
func flipOneBase64Char(t *testing.T, s string) string {
	t.Helper()
	b := []byte(s)
	for i := range b {
		if (b[i] >= 'a' && b[i] < 'z') || (b[i] >= 'A' && b[i] < 'Z') {
			b[i]++
			return string(b)
		}
	}
	t.Fatalf("no flippable base64 character in %q", s)
	return ""
}

// TestMachineFileVerify_ServerFixtures_RejectsNonV2Alg is the M1 regression in
// its security-relevant direction: the +v2 marker is mandatory, and the check
// is an equality test on the last segment, not a substring search.
//
// A v1 file carried no meta.exp inside the signed payload and derived its AES
// key by zero-padding the license key instead of through HKDF, so accepting
// one reinstates both weaknesses. A `strings.Contains(alg, "v2")` test — which
// is how three sibling SDKs "passed" — would also wave through the +v3 and
// +v2junk cases below.
func TestMachineFileVerify_ServerFixtures_RejectsNonV2Alg(t *testing.T) {
	for _, fx := range loadServerMachineFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			scheme, pub := fx.scheme(t), fx.publicKey(t)
			licenseKey, fingerprint := fx.creds()
			base := strings.TrimSuffix(fx.Alg, "+v2")

			for _, alg := range []string{
				base,               // pre-v2 file
				base + "+v3",       // a future/unknown format
				base + "+v2junk",   // trailing garbage
				base + "+v2+extra", // marker not last
			} {
				file := fx.parse(t)
				file.Now = atEpoch()
				file.Alg = alg
				_, err := file.Verify(scheme, pub, licenseKey, fingerprint)
				if err == nil {
					t.Errorf("Verify() accepted alg %q", alg)
					continue
				}
				// Rejected by the alg gate, before any crypto primitive:
				// the signature over enc is untouched and would still
				// verify, so an ErrInvalidSignature here would mean the
				// gate ran too late.
				if errors.Is(err, ErrInvalidSignature) {
					t.Errorf("alg %q rejected as ErrInvalidSignature; the alg gate must run before signature verification", alg)
				}
			}

			// An unrecognized encoding prefix is refused too. This one is
			// caught after signature verification rather than at the gate
			// — the marker and suffix are both well-formed — so it carries
			// no ordering assertion, only the rejection.
			file := fx.parse(t)
			file.Now = atEpoch()
			file.Alg = "x" + fx.Alg
			if _, err := file.Verify(scheme, pub, licenseKey, fingerprint); err == nil {
				t.Errorf("Verify() accepted alg %q", file.Alg)
			}
		})
	}
}

// TestMachineFileVerify_ServerFixtures_SchemeComesFromTheCaller pins the rule
// that survives the M1 fix: the signing scheme is the caller's to supply, and
// the file's alg is only ever a cross-check.
//
// "rsa-sha256" is the suffix the server emits for BOTH RSA_2048_PKCS1_SIGN and
// RSA_2048_JWT_RS256, so the suffix cannot identify the scheme. The same
// fixture bytes therefore verify under PKCS1 and are refused under JWT_RS256,
// up front, before any parsing.
func TestMachineFileVerify_ServerFixtures_SchemeComesFromTheCaller(t *testing.T) {
	var ran int
	for _, fx := range loadServerMachineFixtures(t) {
		if fx.scheme(t) != SchemeRSA2048PKCS1Sign {
			continue
		}
		ran++
		t.Run(fx.Name, func(t *testing.T) {
			pub := fx.publicKey(t)
			licenseKey, fingerprint := fx.creds()

			// The file's own alg cannot tell these two apart.
			pkcs1Suffix, err := schemeAlgSuffix(SchemeRSA2048PKCS1Sign)
			if err != nil {
				t.Fatalf("schemeAlgSuffix: %v", err)
			}
			jwtSuffix, err := schemeAlgSuffix(SchemeRSA2048JWTRS256)
			if err != nil {
				t.Fatalf("schemeAlgSuffix: %v", err)
			}
			if pkcs1Suffix != jwtSuffix {
				t.Fatalf("suffixes diverged (%q vs %q); this test's premise no longer holds", pkcs1Suffix, jwtSuffix)
			}

			file := fx.parse(t)
			file.Now = atEpoch()
			if _, err := file.Verify(SchemeRSA2048PKCS1Sign, pub, licenseKey, fingerprint); err != nil {
				t.Fatalf("Verify(PKCS1) error = %v, want success", err)
			}

			file = fx.parse(t)
			file.Now = atEpoch()
			if _, err := file.Verify(SchemeRSA2048JWTRS256, pub, licenseKey, fingerprint); !errors.Is(err, ErrSchemeNotSupported) {
				t.Errorf("Verify(JWT_RS256) error = %v, want ErrSchemeNotSupported", err)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no rsa-sha256 fixtures in the manifest; the scheme-ambiguity rule is untested")
	}
}

// TestMachineFileVerify_ServerFixtures_WrongSchemeRejectedByCrossCheck covers
// the other half of that rule: a caller passing a scheme whose suffix does not
// match the file it downloaded is caught by the cross-check, before any crypto
// primitive runs.
func TestMachineFileVerify_ServerFixtures_WrongSchemeRejectedByCrossCheck(t *testing.T) {
	all := []LicenseScheme{SchemeEd25519Sign, SchemeECDSAP256Sign, SchemeRSA2048PKCS1Sign, SchemeRSA2048PKCS1PSSSign}
	for _, fx := range loadServerMachineFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			want := fx.scheme(t)
			wantSuffix, err := schemeAlgSuffix(want)
			if err != nil {
				t.Fatalf("schemeAlgSuffix: %v", err)
			}
			licenseKey, fingerprint := fx.creds()
			for _, other := range all {
				otherSuffix, err := schemeAlgSuffix(other)
				if err != nil {
					t.Fatalf("schemeAlgSuffix: %v", err)
				}
				if otherSuffix == wantSuffix {
					continue
				}
				file := fx.parse(t)
				file.Now = atEpoch()
				if _, err := file.Verify(other, fx.publicKey(t), licenseKey, fingerprint); err == nil {
					t.Errorf("Verify() accepted scheme %s against a %q file", other, fx.Alg)
				}
			}
		})
	}
}

// TestParseMachineFileAlg is the unit-level table for the M1 parser. Both the
// encoding prefix ("aes-256-gcm") and the signing suffix ("rsa-pss-sha256")
// contain the hyphen the segments are built from, so the split has to be
// anchored on the first and last "+" and nothing else.
func TestParseMachineFileAlg(t *testing.T) {
	tests := []struct {
		alg        string
		wantPrefix string
		wantSuffix string
		wantErr    bool
	}{
		{alg: "base64+ed25519+v2", wantPrefix: "base64", wantSuffix: "ed25519"},
		{alg: "aes-256-gcm+ed25519+v2", wantPrefix: "aes-256-gcm", wantSuffix: "ed25519"},
		{alg: "base64+ecdsa-p256+v2", wantPrefix: "base64", wantSuffix: "ecdsa-p256"},
		{alg: "aes-256-gcm+ecdsa-p256+v2", wantPrefix: "aes-256-gcm", wantSuffix: "ecdsa-p256"},
		{alg: "base64+rsa-sha256+v2", wantPrefix: "base64", wantSuffix: "rsa-sha256"},
		{alg: "base64+rsa-pss-sha256+v2", wantPrefix: "base64", wantSuffix: "rsa-pss-sha256"},
		{alg: "aes-256-gcm+rsa-pss-sha256+v2", wantPrefix: "aes-256-gcm", wantSuffix: "rsa-pss-sha256"},

		{alg: "base64+ed25519", wantErr: true},             // pre-v2
		{alg: "aes-256-gcm+rsa-pss-sha256", wantErr: true}, // pre-v2, hyphenated both sides
		{alg: "base64+ed25519+v3", wantErr: true},
		{alg: "base64+ed25519+v2junk", wantErr: true},
		{alg: "base64+ed25519+v2+extra", wantErr: true},
		{alg: "base64", wantErr: true},
		{alg: "", wantErr: true},
		{alg: "+ed25519+v2", wantErr: true},
		{alg: "base64++v2", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			prefix, suffix, err := parseMachineFileAlg(tc.alg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMachineFileAlg(%q) = (%q, %q, nil), want an error", tc.alg, prefix, suffix)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMachineFileAlg(%q) error = %v", tc.alg, err)
			}
			if prefix != tc.wantPrefix || suffix != tc.wantSuffix {
				t.Errorf("parseMachineFileAlg(%q) = (%q, %q), want (%q, %q)", tc.alg, prefix, suffix, tc.wantPrefix, tc.wantSuffix)
			}
		})
	}
}

// TestSplitEncryptedEnc is the unit-level table for the M2 splitter.
func TestSplitEncryptedEnc(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 12))
	cipher := base64.StdEncoding.EncodeToString(make([]byte, 40))
	short := base64.StdEncoding.EncodeToString(make([]byte, 15))

	if n, c, err := splitEncryptedEnc(nonce + "." + cipher); err != nil {
		t.Errorf("splitEncryptedEnc() error = %v", err)
	} else if len(n) != 12 || len(c) != 40 {
		t.Errorf("split lengths = (%d, %d), want (12, 40)", len(n), len(c))
	}

	for name, enc := range map[string]string{
		"no separator":     nonce + cipher,
		"two separators":   nonce + "." + cipher + "." + cipher,
		"bad nonce b64":    "!!!." + cipher,
		"bad cipher b64":   nonce + ".!!!",
		"ciphertext short": nonce + "." + short,
	} {
		if _, _, err := splitEncryptedEnc(enc); err == nil {
			t.Errorf("splitEncryptedEnc(%s) succeeded, want an error", name)
		}
	}
}
