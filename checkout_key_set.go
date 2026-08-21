package tamga

// checkout_key_set.go holds the rotation-aware verification entry points:
// (*LicenseFile).VerifyWithKeySet and (*MachineFile).VerifyWithKeySet.
//
// They are additive. (*LicenseFile).Verify and (*MachineFile).Verify keep
// their exact signatures and behaviour and remain the right call for an
// application that holds one key and knows it — these are for the case that
// one key cannot express: an account that has rotated, where an authentic
// file may have been signed by a key that is no longer current.
//
// # Ordering, and why it is not the obvious way round
//
// The obvious implementation reads the file's kid claim first and uses it to
// look a key up. That inverts the one rule the rest of the checkout code is
// built on and states in (*LicenseFile).Verify's own doc comment —
// "an attacker-controlled file never reaches any decoding/decryption/
// JSON-parsing step without first passing signature verification" — because
// the claim lives INSIDE the signed (and possibly encrypted) payload, so
// reading it means parsing attacker-supplied bytes before anything has
// vouched for them.
//
// So these do the opposite. Every key in the set is tried against the
// signature first, and the success path never touches the payload
// unverified: that documented invariant stays literally true for every file
// that verifies. The claim is read only after every key has failed — at
// which point the file is already known not to be authentic under anything
// the caller trusts, it is going to be rejected either way, and the only
// remaining question is which of two errors to report. Its value picks an
// error label and is used for nothing else. It can never introduce a key,
// only select among keys the caller already supplied, which is the same
// discipline JWS kid handling needs and for the same reason.
//
// The cost is at most one signature check per key the account has ever
// held. For Ed25519 that is microseconds, on a set that is realistically a
// handful of entries.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	internalcrypto "github.com/tamga-sh/tamga-go/internal/crypto"
)

// VerifiedLicenseFile is what (*LicenseFile).VerifyWithKeySet returns: the
// same payload (*LicenseFile).Verify produces, plus the key it actually
// verified under.
//
// A distinct type rather than a field added to LicensePayload, deliberately:
// adding a field to a struct callers may build with an unkeyed composite
// literal breaks their build, and on a 1.x module whose consumers pin ^1.2
// and upgrade into patches automatically that is not a cost worth paying for
// a diagnostic.
type VerifiedLicenseFile struct {
	// Payload is exactly what (*LicenseFile).Verify returns for the same
	// file — the decoded licence and the signed claims.
	Payload *LicensePayload
	// Key is the published key whose signature check passed.
	//
	// Worth inspecting even on success: Key.IsRetired() means the file is
	// authentic and was issued before the account's last rotation. Nothing
	// is wrong with it, and it must not be reported to a user as a problem
	// — but whatever hands these files out is due a fresh checkout.
	Key SigningKey
}

// VerifiedMachineFile is what (*MachineFile).VerifyWithKeySet returns — see
// VerifiedLicenseFile, which it mirrors exactly.
type VerifiedMachineFile struct {
	// Payload is exactly what (*MachineFile).Verify returns for the same
	// file.
	Payload *MachinePayload
	// Key is the published key whose signature check passed;
	// Key.IsRetired() reports a pre-rotation file.
	Key SigningKey
}

// claimsProbe reads nothing but the meta claims out of a decoded payload.
// Used only on the failure path of the VerifyWithKeySet methods, to recover
// the kid of a file that verified under no key at all.
type claimsProbe struct {
	Meta *LicenseFileClaims `json:"meta"`
}

// unverifiedKeyID extracts the kid claim from an already-decoded payload
// whose signature did NOT check out, returning "" when there is nothing
// readable there.
//
// Every caller must treat the result as a diagnostic string and nothing
// more: it came from bytes no key vouched for. It is used to choose between
// two rejections, never to accept anything.
func unverifiedKeyID(plaintext []byte) string {
	var probe claimsProbe
	if err := json.Unmarshal(plaintext, &probe); err != nil || probe.Meta == nil {
		return ""
	}
	return probe.Meta.KeyID
}

// VerifyWithKeySet is (*LicenseFile).Verify against a set of trusted keys
// instead of a single one — the call that makes an account's signing-key
// rotation survivable for files already in the field.
//
// Verifying against one embedded key reports a file signed before the
// rotation with exactly the error a forged file produces. Through a key set
// the outcomes are distinct, and they call for opposite responses:
//
//   - it verifies under some key in the set → success. Inspect
//     VerifiedLicenseFile.Key.IsRetired() to learn whether that key was the
//     current one.
//   - the kid it names is not in the set → *UnknownSigningKeyError, matching
//     errors.Is(err, ErrUnknownSigningKey). The file is very likely
//     authentic and the key set is stale: refresh it with
//     (*Client).GetSigningKeySet, or ship an application update carrying
//     the new public key. Do NOT report this to a user as tampering.
//   - the kid it names is UnpublishedSigningKeyID →
//     *UnknownSigningKeyError matching errors.Is(err,
//     ErrSigningKeyNotPublished) instead. Refreshing will not help: the
//     account that signed the file has published no Ed25519 key at all and
//     an operator has to rotate one in.
//   - the set holds nothing usable (it is empty) → ErrNoUsableSigningKey.
//     Nothing about the file was judged, because there was nothing to judge
//     it against.
//   - the kid IS in the set and the signature still fails →
//     ErrInvalidSignature. The named key is right here and does not vouch
//     for these bytes. That is tampering, not rotation. Refuse the file.
//
// Everything past a successful signature check is identical to Verify: the
// same decode, the same decryption under licenseKey for an
// AlgAES256GCMEd25519 file, the same ErrMissingClaims for a pre-v2 payload
// and the same *ExpiredError from the signed exp claim, with the same
// clockSkewToleranceSeconds allowance and the same overridable f.Now clock.
//
// licenseKey is required only for the encrypted variant, exactly as in
// Verify — pass "" for a plain AlgBase64Ed25519 file.
func (f *LicenseFile) VerifyWithKeySet(keys *SigningKeySet, licenseKey string) (*VerifiedLicenseFile, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(f.Sig)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in license file signature: %w", err)
	}
	if keys.Len() == 0 {
		return nil, fmt.Errorf("%w: no Ed25519 signing keys were supplied", ErrNoUsableSigningKey)
	}

	// Signature first, against every key held — the success path never
	// reads a byte of the payload before one of these passes.
	for _, entry := range keys.entries {
		if !internalcrypto.VerifyEd25519(entry.publicKey, []byte(f.Enc), sigBytes) {
			continue
		}
		plaintext, derr := f.decodePlaintext(licenseKey)
		if derr != nil {
			return nil, derr
		}
		payload, perr := f.payloadFrom(plaintext)
		if perr != nil {
			return nil, perr
		}
		return &VerifiedLicenseFile{Payload: payload, Key: entry.key}, nil
	}

	// Nothing verified, so the file is rejected whatever happens next. Only
	// now is the payload worth decoding, and only for the one claim that
	// decides which rejection is the honest one.
	plaintext, derr := f.decodePlaintext(licenseKey)
	if derr != nil {
		return nil, unverifiableFileError(derr)
	}
	return nil, keySetFailure(keys, unverifiedKeyID(plaintext))
}

// VerifyWithKeySet is (*MachineFile).Verify against a set of trusted keys —
// see (*LicenseFile).VerifyWithKeySet, whose outcomes and reasoning this
// mirrors exactly. scheme, licenseKey and fingerprint mean precisely what
// they mean on Verify, including the up-front ErrSchemeNotSupported refusal
// of SchemeRSA2048JWTRS256 and the alg-suffix cross-check against scheme.
//
// ⚠️ Ed25519-signed machine files only, and the reason is worth
// understanding rather than working around. A .machine file under an RSA or
// ECDSA scheme is signed with the account's RSA/ECDSA private key
// (check_out_machine.rs:86-99), and those keys are neither published by
// GET /signing-keys nor rotated by anything — only Ed25519 is
// (`rotate_ed25519`). So the defect this method exists for cannot arise for
// them, and there is nothing for a key set to hold. Passing any scheme but
// SchemeEd25519Sign returns ErrNoUsableSigningKey; verify those files with
// Verify and the public key you already have.
//
// That also explains a claim that would otherwise look like a bug: an
// RSA-signed machine file still carries a kid, and it names the account's
// ED25519 key, because check_out_machine.rs:127 derives the claim from
// account.ed25519_public_key whatever scheme actually signed the bytes.
// Reading that kid and hunting for the key it names would find a real,
// published key that cannot possibly verify the signature — and report an
// authentic file as a forgery, which is the exact failure this whole file
// exists to prevent. Hence the refusal up front.
func (f *MachineFile) VerifyWithKeySet(scheme LicenseScheme, keys *SigningKeySet, licenseKey, fingerprint string) (*VerifiedMachineFile, error) {
	if scheme == SchemeRSA2048JWTRS256 {
		return nil, ErrSchemeNotSupported
	}

	// Same alg parse and suffix cross-check Verify performs, in the same
	// order and for the same defense-in-depth reason: catch a caller
	// passing a scheme that does not match the file they downloaded before
	// any crypto primitive runs.
	encPrefix, algSuffix, err := parseMachineFileAlg(f.Alg)
	if err != nil {
		return nil, err
	}
	expectedSuffix, err := schemeAlgSuffix(scheme)
	if err != nil {
		return nil, err
	}
	if algSuffix != expectedSuffix {
		return nil, fmt.Errorf("tamga: machine file declares alg suffix %q, expected %q for scheme %s", algSuffix, expectedSuffix, scheme)
	}
	if scheme != SchemeEd25519Sign {
		return nil, fmt.Errorf("%w: scheme %s is signed with the account's RSA/ECDSA key, which is never published or rotated — verify it with (*MachineFile).Verify instead", ErrNoUsableSigningKey, scheme)
	}
	if keys.Len() == 0 {
		return nil, fmt.Errorf("%w: no Ed25519 signing keys were supplied", ErrNoUsableSigningKey)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(f.Sig)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in machine file signature: %w", err)
	}

	for _, entry := range keys.entries {
		verified, verr := verifyMachineFileSignature(scheme, entry.publicKey, []byte(f.Enc), sigBytes)
		if verr != nil {
			return nil, verr
		}
		if !verified {
			continue
		}
		plaintext, derr := f.decodePlaintext(encPrefix, licenseKey, fingerprint)
		if derr != nil {
			return nil, derr
		}
		payload, perr := f.payloadFrom(plaintext)
		if perr != nil {
			return nil, perr
		}
		return &VerifiedMachineFile{Payload: payload, Key: entry.key}, nil
	}

	plaintext, derr := f.decodePlaintext(encPrefix, licenseKey, fingerprint)
	if derr != nil {
		return nil, unverifiableFileError(derr)
	}
	return nil, keySetFailure(keys, unverifiedKeyID(plaintext))
}

// unverifiableFileError decides what to report when no key verified a file
// AND its payload could not even be decoded to read the kid.
//
// A missing licence key or fingerprint is the caller's own omission, is
// decided entirely by their inputs and the file's public alg string, and
// tells an attacker nothing about the file — so it is surfaced as itself
// rather than buried, because "you forgot the decryption material" is far
// more actionable than "invalid signature". Anything else means the bytes
// are malformed or undecryptable, and after every key has already failed
// there is nothing to distinguish that from a forgery.
func unverifiableFileError(err error) error {
	if errors.Is(err, ErrLicenseKeyRequired) || errors.Is(err, ErrFingerprintRequired) {
		return err
	}
	return ErrInvalidSignature
}

// keySetFailure turns a claimed kid into the right rejection, having
// established that no key in the set verified the file.
//
// The distinction it draws is the entire point of verifying through a key
// set. A kid the set does not hold means the set is behind the account (or,
// for UnpublishedSigningKeyID, that the account never published a key) —
// the file is probably authentic and the customer should not be refused
// over it. A kid the set DOES hold, whose key nonetheless rejects the
// bytes, is tampering: the right key is present and it says no.
//
// An unreadable or absent kid falls to ErrInvalidSignature, which fails
// closed. There is nothing to reason about, so nothing is assumed in the
// file's favour.
func keySetFailure(keys *SigningKeySet, kid string) error {
	if kid == "" {
		return ErrInvalidSignature
	}
	if _, held := keys.find(kid); held {
		return ErrInvalidSignature
	}
	return &UnknownSigningKeyError{KeyID: kid, Available: keys.KeyIDs()}
}
