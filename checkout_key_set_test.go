package tamga

// checkout_key_set_test.go covers the rotation-aware verification entry
// points.
//
// The machine-file half runs entirely against
// testdata/server-machine-file-fixtures/ — certificates the tamga-api
// server's own encoder produced, never this SDK — so the kid claim these
// tests read is a real one, sitting in real signed bytes, at the real offset
// in the real wire format.
//
// The licence-file half builds its PEMs with buildLicensePEM
// (checkout_license_test.go), because the property under test there is which
// KEY gets selected out of a set, and that is independent of the wire format
// — which is already pinned separately by that file's own fixture and
// regression tests, and end-to-end by the machine fixtures here. A
// self-generated fixture is never used to establish a wire format in this
// repo; it is used here only to mint the several distinctly-signed files
// that a rotation scenario needs and that no fixture set contains.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	internalcrypto "github.com/tamga-sh/tamga-go/internal/crypto"
)

// keyedLicensePayloadJSON builds a licence-file payload naming kid in its
// signed meta claims, with exp when nonzero.
func keyedLicensePayloadJSON(kid string, exp int64) string {
	expField := ""
	if exp != 0 {
		expField = fmt.Sprintf(`,"exp":%d`, exp)
	}
	return `{"data":{"id":"lic-id","type":"licenses","attributes":{"name":"Acme Corp","key":"lic-abc123",` +
		`"status":"ACTIVE","expiry":null,"suspended":false,"protected":false,"uses":0,"scheme":null,` +
		`"encrypted":false,"strict":false,"floating":false,"max_machines":null,"max_uses":null,` +
		`"max_users":null,"last_validated_at":null,"last_check_in_at":null,"last_check_out_at":null,` +
		`"machines_count":0,"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}},` +
		fmt.Sprintf(`"meta":{"iat":1767225600,"jti":"test-jti","kid":%q%s}}`, kid, expField)
}

// rotatedKey is one Ed25519 keypair plus the published resource that names
// it, so a test can talk about "the key that signed this" and "the key set
// that does or does not hold it" in the same terms the server does.
type rotatedKey struct {
	resource SigningKey
	kid      string
	priv     ed25519.PrivateKey
}

func newRotatedKey(t *testing.T, retiredAt string) rotatedKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	kid := KeyID(b64)
	var retired *string
	status := "active"
	if retiredAt != "" {
		retired, status = &retiredAt, "retired"
	}
	return rotatedKey{
		priv: priv,
		kid:  kid,
		resource: SigningKey{
			ID:   kid,
			Type: "signing-keys",
			Attributes: SigningKeyAttributes{
				Algorithm: ed25519Algorithm,
				PublicKey: b64,
				Status:    status,
				Created:   "2026-01-01T00:00:00Z",
				Retired:   retired,
			},
		},
	}
}

// licenseFileSignedBy mints a .lic file signed with signer, whose kid claim
// names claimKid. Passing a claimKid that does not match signer is how a
// tampered or mislabelled file is expressed.
func licenseFileSignedBy(t *testing.T, signer rotatedKey, claimKid string, exp int64) *LicenseFile {
	t.Helper()
	pem := buildLicensePEM(t, keyedLicensePayloadJSON(claimKid, exp), signer.priv, nil, false)
	file, err := ParseLicenseFile(pem)
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	file.Now = atEpoch()
	return file
}

// TestLicenseFileVerifyWithKeySet_VerifiesAFileSignedBeforeTheRotation is
// THE regression test for defect M22.
//
// Before this existed, an offline file signed under the account's previous
// key failed against the current key with ErrInvalidSignature — the exact
// error a forgery produces — so a paying customer holding a perfectly valid
// file was locked out and the message sent support to the wrong place.
func TestLicenseFileVerifyWithKeySet_VerifiesAFileSignedBeforeTheRotation(t *testing.T) {
	oldKey := newRotatedKey(t, "2026-06-01T00:00:00Z")
	newKey := newRotatedKey(t, "")
	file := licenseFileSignedBy(t, oldKey, oldKey.kid, 0)

	// The account has rotated: the current key is newKey, and the file in
	// the customer's hands was signed by oldKey.
	set := NewSigningKeySet([]SigningKey{newKey.resource, oldKey.resource})

	verified, err := file.VerifyWithKeySet(set, "")
	if err != nil {
		t.Fatalf("VerifyWithKeySet() error = %v, want a pre-rotation file to verify against the published key set", err)
	}
	if verified.Key.ID != oldKey.kid {
		t.Errorf("Key.ID = %q, want the retired key %q that actually signed the file", verified.Key.ID, oldKey.kid)
	}
	if !verified.Key.IsRetired() {
		t.Error("Key.IsRetired() = false, want true so a caller can prompt for a fresh checkout")
	}
	if verified.Payload == nil || verified.Payload.Data.ID != "lic-id" {
		t.Errorf("Payload = %+v, want the decoded licence", verified.Payload)
	}
	if verified.Payload.Claims.KeyID != oldKey.kid {
		t.Errorf("Claims.KeyID = %q, want %q", verified.Payload.Claims.KeyID, oldKey.kid)
	}

	// And the single-key entry point still reports exactly the old failure
	// against the current key, which is the behaviour being worked around
	// rather than changed.
	currentPub, err := base64.StdEncoding.DecodeString(newKey.resource.Attributes.PublicKey)
	if err != nil {
		t.Fatalf("decode current public key: %v", err)
	}
	if _, err := file.Verify(ed25519.PublicKey(currentPub), ""); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify(current key) error = %v, want ErrInvalidSignature — the defect being worked around", err)
	}
}

// TestLicenseFileVerifyWithKeySet_StaleKeySetIsNotReportedAsAForgery pins
// the distinction the whole feature exists for: an unknown kid and a bad
// signature are different incidents calling for opposite responses.
func TestLicenseFileVerifyWithKeySet_StaleKeySetIsNotReportedAsAForgery(t *testing.T) {
	shipped := newRotatedKey(t, "")
	unknown := newRotatedKey(t, "")
	file := licenseFileSignedBy(t, unknown, unknown.kid, 0)

	set := NewSigningKeySet([]SigningKey{shipped.resource})

	_, err := file.VerifyWithKeySet(set, "")
	if !errors.Is(err, ErrUnknownSigningKey) {
		t.Fatalf("error = %v, want ErrUnknownSigningKey", err)
	}
	if errors.Is(err, ErrInvalidSignature) {
		t.Fatal("a stale key set matched ErrInvalidSignature; that is the defect — it reports an authentic file as forged")
	}
	if errors.Is(err, ErrSigningKeyNotPublished) {
		t.Error("a stale key set must not match ErrSigningKeyNotPublished, which no client action can fix")
	}
	var unknownErr *UnknownSigningKeyError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("errors.As(*UnknownSigningKeyError) = false for %v", err)
	}
	if unknownErr.KeyID != unknown.kid {
		t.Errorf("KeyID = %q, want the kid the file names, %q", unknownErr.KeyID, unknown.kid)
	}
	if len(unknownErr.Available) != 1 || unknownErr.Available[0] != shipped.kid {
		t.Errorf("Available = %v, want the kids the set held, [%s]", unknownErr.Available, shipped.kid)
	}
	if !strings.Contains(unknownErr.Error(), unknown.kid) {
		t.Errorf("Error() = %q, want the claimed kid in the message", unknownErr.Error())
	}
}

// TestLicenseFileVerifyWithKeySet_AKnownKidThatStillFailsIsAForgery is the
// other half of that distinction, and the one that keeps the feature honest:
// selecting keys by kid must not become a way to excuse a bad signature.
func TestLicenseFileVerifyWithKeySet_AKnownKidThatStillFailsIsAForgery(t *testing.T) {
	held := newRotatedKey(t, "")
	attacker := newRotatedKey(t, "")

	// Signed by a key nobody trusts, but claiming the kid of one the set
	// does hold — the shape of a forgery dressed up as a rotation.
	file := licenseFileSignedBy(t, attacker, held.kid, 0)
	set := NewSigningKeySet([]SigningKey{held.resource})

	_, err := file.VerifyWithKeySet(set, "")
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v, want ErrInvalidSignature: the named key is present and rejects these bytes", err)
	}
	if errors.Is(err, ErrUnknownSigningKey) {
		t.Error("a forgery naming a held kid must not be reported as a stale key set")
	}
}

// TestLicenseFileVerifyWithKeySet_UnpublishedAccountIsItsOwnCondition pins
// the e3b0c44298fc1c14 case. An account whose ed25519_public_key column was
// never populated signs every file with KeyID(""), and telling a user to
// refresh a key set that can never contain that key is the wrong advice.
func TestLicenseFileVerifyWithKeySet_UnpublishedAccountIsItsOwnCondition(t *testing.T) {
	held := newRotatedKey(t, "")
	signer := newRotatedKey(t, "")
	file := licenseFileSignedBy(t, signer, UnpublishedSigningKeyID, 0)
	set := NewSigningKeySet([]SigningKey{held.resource})

	_, err := file.VerifyWithKeySet(set, "")
	if !errors.Is(err, ErrSigningKeyNotPublished) {
		t.Fatalf("error = %v, want ErrSigningKeyNotPublished", err)
	}
	if errors.Is(err, ErrUnknownSigningKey) {
		t.Error("ErrSigningKeyNotPublished must not also match ErrUnknownSigningKey: " +
			"refreshing the key set cannot fix an account that has published no key")
	}
	if errors.Is(err, ErrInvalidSignature) {
		t.Error("an unpublished-key account must not read as a forgery")
	}
	var unknownErr *UnknownSigningKeyError
	if !errors.As(err, &unknownErr) || unknownErr.KeyID != UnpublishedSigningKeyID {
		t.Errorf("errors.As KeyID = %v, want %q", err, UnpublishedSigningKeyID)
	}
	if !strings.Contains(unknownErr.Error(), "published no Ed25519 signing key") {
		t.Errorf("Error() = %q, want it to name the actual condition", unknownErr.Error())
	}
}

func TestLicenseFileVerifyWithKeySet_EmptyOrNilSetIsAConfigurationError(t *testing.T) {
	signer := newRotatedKey(t, "")
	file := licenseFileSignedBy(t, signer, signer.kid, 0)

	for name, set := range map[string]*SigningKeySet{
		"nil":          nil,
		"empty":        NewSigningKeySet(nil),
		"all rows bad": NewSigningKeySet([]SigningKey{signingKeyResource("x", "ml-dsa-44", zeroKeyB64, nil)}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := file.VerifyWithKeySet(set, "")
			if !errors.Is(err, ErrNoUsableSigningKey) {
				t.Errorf("error = %v, want ErrNoUsableSigningKey", err)
			}
			if errors.Is(err, ErrInvalidSignature) {
				t.Error("nothing was judged about the file, so it must not read as a forgery")
			}
		})
	}
}

// TestLicenseFileVerifyWithKeySet_AgreesWithVerifyOnTheHappyPath makes sure
// the new entry point is the old one plus key selection, not a second
// implementation that can drift.
func TestLicenseFileVerifyWithKeySet_AgreesWithVerifyOnTheHappyPath(t *testing.T) {
	signer := newRotatedKey(t, "")
	file := licenseFileSignedBy(t, signer, signer.kid, 0)
	pub, err := base64.StdEncoding.DecodeString(signer.resource.Attributes.PublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}

	direct, err := file.Verify(ed25519.PublicKey(pub), "")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	viaSet, err := file.VerifyWithKeySet(NewSigningKeySet([]SigningKey{signer.resource}), "")
	if err != nil {
		t.Fatalf("VerifyWithKeySet() error = %v", err)
	}

	wantJSON, err := json.Marshal(direct)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gotJSON, err := json.Marshal(viaSet.Payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("payloads differ:\n Verify:            %s\n VerifyWithKeySet:  %s", wantJSON, gotJSON)
	}
}

func TestLicenseFileVerifyWithKeySet_EnforcesTheSignedExpClaim(t *testing.T) {
	signer := newRotatedKey(t, "")
	const exp = 1767225600
	pem := buildLicensePEM(t, keyedLicensePayloadJSON(signer.kid, exp), signer.priv, nil, false)
	file, err := ParseLicenseFile(pem)
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	file.Now = at(exp + clockSkewToleranceSeconds + 1)

	_, err = file.VerifyWithKeySet(NewSigningKeySet([]SigningKey{signer.resource}), "")
	var expired *ExpiredError
	if !errors.As(err, &expired) {
		t.Fatalf("error = %v, want *ExpiredError — the signed exp must be enforced on this path too", err)
	}
	if expired.ExpiresAt != exp {
		t.Errorf("ExpiresAt = %d, want %d", expired.ExpiresAt, exp)
	}
}

func TestLicenseFileVerifyWithKeySet_EncryptedFileRoundTrip(t *testing.T) {
	signer := newRotatedKey(t, "")
	const licenseKey = "TAMGA-TEST-LICENSE-KEY"
	aesKey, err := internalcrypto.DeriveLicenseFileKey(licenseKey)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	pem := buildLicensePEM(t, keyedLicensePayloadJSON(signer.kid, 0), signer.priv, &aesKey, false)
	file, err := ParseLicenseFile(pem)
	if err != nil {
		t.Fatalf("ParseLicenseFile() error = %v", err)
	}
	file.Now = atEpoch()
	set := NewSigningKeySet([]SigningKey{signer.resource})

	verified, err := file.VerifyWithKeySet(set, licenseKey)
	if err != nil {
		t.Fatalf("VerifyWithKeySet() error = %v", err)
	}
	if verified.Payload.Data.ID != "lic-id" {
		t.Errorf("Data.ID = %q", verified.Payload.Data.ID)
	}

	// Omitting the licence key must say so rather than hide behind an
	// invalid-signature error a caller cannot act on.
	if _, err := file.VerifyWithKeySet(set, ""); !errors.Is(err, ErrLicenseKeyRequired) {
		t.Errorf("error = %v, want ErrLicenseKeyRequired", err)
	}
}

// --- machine files, against real server-issued certificates --------------

// ed25519ServerFixtures returns the manifest entries this path can serve:
// Ed25519-signed only, because that is the only algorithm the server ever
// publishes or rotates.
func ed25519ServerFixtures(t *testing.T) []serverMachineFixture {
	t.Helper()
	var out []serverMachineFixture
	for _, fx := range loadServerMachineFixtures(t) {
		if fx.scheme(t) == SchemeEd25519Sign {
			out = append(out, fx)
		}
	}
	if len(out) == 0 {
		t.Fatal("no Ed25519 machine fixtures found")
	}
	return out
}

// decoyKeySetAround wraps a fixture's real key with two unrelated ones, so
// the "try every key" loop is actually exercised rather than passing by
// landing on a single-element set.
func decoyKeySetAround(t *testing.T, publicKeyB64 string) *SigningKeySet {
	t.Helper()
	before := newRotatedKey(t, "2026-01-01T00:00:00Z")
	after := newRotatedKey(t, "")
	real := SigningKey{
		ID:   KeyID(publicKeyB64),
		Type: "signing-keys",
		Attributes: SigningKeyAttributes{
			Algorithm: ed25519Algorithm,
			PublicKey: publicKeyB64,
			Status:    "active",
			Created:   "2026-01-01T00:00:00Z",
		},
	}
	return NewSigningKeySet([]SigningKey{before.resource, real, after.resource})
}

// TestMachineFileVerifyWithKeySet_ServerFixturesVerifyThroughAKeySet runs
// the whole path against bytes the tamga-api encoder produced, with the
// file's real key buried among decoys.
func TestMachineFileVerifyWithKeySet_ServerFixturesVerifyThroughAKeySet(t *testing.T) {
	for _, fx := range ed25519ServerFixtures(t) {
		if fx.Expired {
			continue
		}
		t.Run(fx.Name, func(t *testing.T) {
			file := fx.parse(t)
			file.Now = atEpoch()
			licenseKey, fingerprint := fx.creds()

			verified, err := file.VerifyWithKeySet(SchemeEd25519Sign, decoyKeySetAround(t, fx.PublicKeyB64), licenseKey, fingerprint)
			if err != nil {
				t.Fatalf("VerifyWithKeySet() error = %v", err)
			}
			if verified.Key.ID != fx.KID {
				t.Errorf("Key.ID = %q, want the fixture's kid %q", verified.Key.ID, fx.KID)
			}
			if verified.Payload.Claims.KeyID != fx.KID {
				t.Errorf("Claims.KeyID = %q, want %q", verified.Payload.Claims.KeyID, fx.KID)
			}
			if verified.Payload.Data.ID == "" {
				t.Error("Data.ID is empty; the machine did not decode")
			}
		})
	}
}

// TestMachineFileVerifyWithKeySet_UnknownKidOnARealServerFile proves the
// unverified-kid read works against genuine server bytes at the real offset
// in the real format — not against a payload this SDK laid out itself.
func TestMachineFileVerifyWithKeySet_UnknownKidOnARealServerFile(t *testing.T) {
	for _, fx := range ed25519ServerFixtures(t) {
		if fx.Expired {
			continue
		}
		t.Run(fx.Name, func(t *testing.T) {
			file := fx.parse(t)
			file.Now = atEpoch()
			licenseKey, fingerprint := fx.creds()
			// A key set that has not caught up with the account.
			stale := NewSigningKeySet([]SigningKey{newRotatedKey(t, "").resource})

			_, err := file.VerifyWithKeySet(SchemeEd25519Sign, stale, licenseKey, fingerprint)
			if !errors.Is(err, ErrUnknownSigningKey) {
				t.Fatalf("error = %v, want ErrUnknownSigningKey", err)
			}
			if errors.Is(err, ErrInvalidSignature) {
				t.Fatal("an authentic server file read as a forgery against a stale key set")
			}
			var unknownErr *UnknownSigningKeyError
			if !errors.As(err, &unknownErr) {
				t.Fatalf("errors.As(*UnknownSigningKeyError) = false")
			}
			if unknownErr.KeyID != fx.KID {
				t.Errorf("KeyID = %q, want the kid inside the real signed payload, %q", unknownErr.KeyID, fx.KID)
			}
		})
	}
}

// TestMachineFileVerifyWithKeySet_NonEd25519SchemesAreRefusedUpFront pins
// the boundary. An RSA/ECDSA machine file is signed with a key the server
// never publishes and never rotates, yet its kid claim names the account's
// Ed25519 key anyway (check_out_machine.rs:127). Looking that kid up would
// find a real published key that cannot verify the signature and report an
// authentic file as forged — the exact failure this feature exists to
// prevent. So the refusal is up front and distinguishable.
func TestMachineFileVerifyWithKeySet_NonEd25519SchemesAreRefusedUpFront(t *testing.T) {
	var checked int
	for _, fx := range loadServerMachineFixtures(t) {
		scheme := fx.scheme(t)
		if scheme == SchemeEd25519Sign {
			continue
		}
		checked++
		t.Run(fx.Name, func(t *testing.T) {
			file := fx.parse(t)
			file.Now = atEpoch()
			licenseKey, fingerprint := fx.creds()
			set := decoyKeySetAround(t, zeroKeyB64)

			_, err := file.VerifyWithKeySet(scheme, set, licenseKey, fingerprint)
			if !errors.Is(err, ErrNoUsableSigningKey) {
				t.Fatalf("error = %v, want ErrNoUsableSigningKey for scheme %s", err, scheme)
			}
			if errors.Is(err, ErrInvalidSignature) {
				t.Error("a scheme the key set cannot serve must not read as a forgery")
			}
			if !strings.Contains(err.Error(), "(*MachineFile).Verify") {
				t.Errorf("error = %q, want it to point at the entry point that can verify this file", err)
			}
		})
	}
	if checked == 0 {
		t.Fatal("no non-Ed25519 fixtures were exercised; this test proved nothing")
	}
}

func TestMachineFileVerifyWithKeySet_RejectsJWTRS256BeforeAnythingElse(t *testing.T) {
	file := &MachineFile{Alg: "base64+rsa-sha256+v2", Enc: "x", Sig: "x", Now: atEpoch()}
	if _, err := file.VerifyWithKeySet(SchemeRSA2048JWTRS256, NewSigningKeySet(nil), "", ""); !errors.Is(err, ErrSchemeNotSupported) {
		t.Errorf("error = %v, want ErrSchemeNotSupported", err)
	}
}

func TestMachineFileVerifyWithKeySet_CrossChecksTheAlgSuffixAgainstScheme(t *testing.T) {
	fx := ed25519ServerFixtures(t)[0]
	file := fx.parse(t)
	file.Now = atEpoch()
	// Claim an ECDSA scheme for a file whose alg says ed25519.
	_, err := file.VerifyWithKeySet(SchemeECDSAP256Sign, decoyKeySetAround(t, fx.PublicKeyB64), "", "")
	if err == nil || !strings.Contains(err.Error(), "alg suffix") {
		t.Errorf("error = %v, want the alg-suffix cross-check to fire before key selection", err)
	}
}

func TestMachineFileVerifyWithKeySet_EnforcesTheSignedExpClaim(t *testing.T) {
	var checked int
	for _, fx := range ed25519ServerFixtures(t) {
		if !fx.Expired {
			continue
		}
		checked++
		t.Run(fx.Name, func(t *testing.T) {
			file := fx.parse(t)
			// Wall-clock now: the fixture's exp is already in the past.
			licenseKey, fingerprint := fx.creds()
			_, err := file.VerifyWithKeySet(SchemeEd25519Sign, decoyKeySetAround(t, fx.PublicKeyB64), licenseKey, fingerprint)
			var expired *ExpiredError
			if !errors.As(err, &expired) {
				t.Fatalf("error = %v, want *ExpiredError", err)
			}
		})
	}
	if checked == 0 {
		t.Fatal("no expired Ed25519 fixture was exercised; this test proved nothing")
	}
}

func TestMachineFileVerifyWithKeySet_AgreesWithVerifyOnTheHappyPath(t *testing.T) {
	for _, fx := range ed25519ServerFixtures(t) {
		if fx.Expired {
			continue
		}
		t.Run(fx.Name, func(t *testing.T) {
			licenseKey, fingerprint := fx.creds()

			a := fx.parse(t)
			a.Now = atEpoch()
			direct, err := a.Verify(SchemeEd25519Sign, fx.publicKey(t), licenseKey, fingerprint)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			b := fx.parse(t)
			b.Now = atEpoch()
			viaSet, err := b.VerifyWithKeySet(SchemeEd25519Sign, decoyKeySetAround(t, fx.PublicKeyB64), licenseKey, fingerprint)
			if err != nil {
				t.Fatalf("VerifyWithKeySet() error = %v", err)
			}

			wantJSON, merr := json.Marshal(direct)
			if merr != nil {
				t.Fatalf("marshal: %v", merr)
			}
			gotJSON, merr := json.Marshal(viaSet.Payload)
			if merr != nil {
				t.Fatalf("marshal: %v", merr)
			}
			if string(wantJSON) != string(gotJSON) {
				t.Errorf("payloads differ:\n Verify:           %s\n VerifyWithKeySet: %s", wantJSON, gotJSON)
			}
		})
	}
}
