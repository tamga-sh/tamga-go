package tamga

// signing_key.go is the key-rotation half of offline verification: the
// `signing-keys` resource the server publishes, the `kid` derivation that
// names one, and the SigningKeySet an offline file is verified through.
//
// # The defect this closes
//
// Verifying a .lic or .machine file against one embedded public key
// collapses two completely different outcomes into one error. A file signed
// last month, before the account rotated its signing key, is authentic and
// the licence behind it may well still be valid — but against the current
// key it fails with exactly the error a forgery produces. The customer is
// locked out and the error sends support to the wrong place: "signature
// verification failed" reads as tampering when the real answer is "this
// client's key set is stale".
//
// Every offline file names its signer in a `kid` claim inside the signed
// bytes (LicenseFileClaims.KeyID). This file is what finally makes that
// claim useful: fetch the account's whole key history — retired keys
// included, which is the entire point of the route — and verify through the
// set rather than against a single key.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// keyIDPrefixBytes is how many bytes of the SHA-256 digest the server keeps
// when deriving a `kid`: the first eight, rendered lowercase hex, so every
// `kid` is exactly 16 characters.
const keyIDPrefixBytes = 8

// ed25519Algorithm is the `algorithm` string the server writes for every key
// it publishes. Rotation is `rotate_ed25519` and the insert carries a
// literal 'ed25519' (accounts/signing_keys.rs); nothing writes another
// value today.
const ed25519Algorithm = "ed25519"

// UnpublishedSigningKeyID is the `kid` an account with no Ed25519 public key
// signs everything with: KeyID(""), i.e. the SHA-256 of the empty string.
//
// It is reachable in production, not a theoretical case. Both checkout
// handlers derive the claim with
// `key_id(account.ed25519_public_key.as_deref().unwrap_or_default())`
// (check_out_license.rs:95, check_out_machine.rs:127), so an account whose
// key column was never populated does not fail the checkout — it happily
// signs every file it issues with this one id.
//
// Recognising it is what separates "your key set is stale, refresh it" from
// "the server that issued this file has published no signing key at all".
// The first is fixed on the client, by fetching the key set; the second
// cannot be fixed on the client at any speed and needs an operator to
// rotate a key into the account. Verification surfaces the difference as
// ErrSigningKeyNotPublished rather than ErrUnknownSigningKey — see
// UnknownSigningKeyError.
const UnpublishedSigningKeyID = "e3b0c44298fc1c14"

// KeyID derives the `kid` an offline file signed with publicKeyBase64 will
// name, matching the server's own key_id
// (tamga-api/src/shared/crypto/license_file.rs:70): the first eight bytes of
// SHA-256 over the key, lowercase hex, so a 16-character string.
//
// ⚠️ THE CENTRAL GOTCHA OF THIS FILE: the digest is taken over the base64
// STRING's own bytes, NOT over the 32 key bytes it decodes to. The server
// stores the Ed25519 public half as standard base64 (key_material.rs — "Raw
// 32-byte Ed25519 public key, base64-encoded") and hands that same string
// straight to key_id, so passing the decoded bytes here produces a
// different, wrong id that matches nothing the server ever emitted. This is
// the same shape of mistake as the checkout signature covering enc's base64
// string rather than enc's decoded bytes (see (*LicenseFile).Verify), and it
// fails the same silent way: a self-generated fixture that repeats the
// mistake agrees with itself while nothing real verifies.
// testdata/signing-key-ids.json pins both the correct answer and the wrong
// one for the same key, and signing_key_test.go asserts against both.
//
// No validation is performed and none is wanted: this is a pure function of
// whatever string it is given, exactly as the server's is. The empty string
// is a meaningful input, not an error — see UnpublishedSigningKeyID.
//
// Against a key set fetched from the API you do not need this at all: the
// resource `id` already IS the `kid` (accounts/serializer.rs:102 — "The
// `kid` doubles as the resource id — it is what an offline file names"), so
// NewSigningKeySet indexes by the served id and uses KeyID only to
// cross-check it (SigningKeySet.Mismatched). KeyID earns its keep on the
// offline path, where an application pins public keys in its own binary and
// never calls the API — see NewSigningKeySetFromPublicKeys.
func KeyID(publicKeyBase64 string) string {
	sum := sha256.Sum256([]byte(publicKeyBase64))
	return hex.EncodeToString(sum[:keyIDPrefixBytes])
}

// SigningKey is one `signing-keys` JSON:API resource from
// GET /v1/accounts/{account_id}/signing-keys.
//
// ⚠️ ID is the `kid`, not a UUID. Every other resource in this package is
// identified by a UUID; this one is identified by the same 16-character
// lowercase hex string an offline file's `kid` claim carries, because the
// server sets `id: k.kid` (accounts/serializer.rs:102). Matching a file to
// its key against this route's output therefore needs no local hashing.
type SigningKey struct {
	ID         string               `json:"id"`
	Type       string               `json:"type"`
	Attributes SigningKeyAttributes `json:"attributes"`
}

// SigningKeyAttributes is the attribute bag of a SigningKey.
//
// ⚠️ PublicKey is `publicKey` on the wire — camelCase inside an otherwise
// bare resource. The server's SigningKeyAttributes carries no rename_all;
// the single per-field rename on public_key (accounts/serializer.rs:111) is
// the only exception, and algorithm/status/created/retired are all spelled
// plainly. Applying camelCase to the whole bag is as wrong as applying
// snake_case to all of it — derive any fixture from the serializer, never
// from these struct tags.
//
// Algorithm and Status are open strings rather than typed enums on purpose.
// A future algorithm or an unrecognised status must decode rather than fail
// the whole response: one unreadable row that stranded the entire key set
// would strand every file the account has ever signed with it.
type SigningKeyAttributes struct {
	// Retired leads the struct only to satisfy govet's fieldalignment
	// check; field order here carries no wire meaning.
	//
	// ⚠️ It is ABSENT while a key is active, not null — the server skips
	// the field entirely (`skip_serializing_if = "Option::is_none"`), which
	// is why it is a *string: nil means "still active", not "retired at the
	// zero time".
	Retired   *string `json:"retired,omitempty"`
	Algorithm string  `json:"algorithm"`
	PublicKey string  `json:"publicKey"`
	Status    string  `json:"status"`
	Created   string  `json:"created"`
}

// IsRetired reports whether the server has retired this key.
//
// A file that verified under a retired key is authentic and nothing is
// wrong with it — it was simply issued before the account's last rotation.
// It is still worth acting on: whatever hands these files out is due a
// fresh checkout, because a rotation retires a key rather than destroying
// it and only an operator deleting the key (the deliberate,
// breaks-every-old-file response to a compromise) ever stops it verifying.
func (k SigningKey) IsRetired() bool {
	return k.Attributes.Retired != nil
}

// signingKeyEntry is one usable member of a SigningKeySet: the resource as
// published, its decoded 32-byte public key, and the id KeyID derives from
// the key locally — kept alongside the served id so a mismatch between the
// two is detectable (SigningKeySet.Mismatched) without either one being
// allowed to reject a file on its own.
type signingKeyEntry struct {
	key        SigningKey
	computedID string
	publicKey  ed25519.PublicKey
}

// SigningKeySet is the set of Ed25519 public keys an offline file is
// allowed to have been signed by, indexed by the `kid` its claims name.
//
// Build one from the account's published keys with
// (*Client).GetSigningKeySet or NewSigningKeySet, or — with no network at
// all — from keys pinned in the application binary with
// NewSigningKeySetFromPublicKeys. Then pass it to
// (*LicenseFile).VerifyWithKeySet or (*MachineFile).VerifyWithKeySet.
//
// # Why a set, and why the kid never chooses the key
//
// The `kid` claim lives INSIDE the signed payload, so reading it to pick a
// key would mean interpreting attacker-supplied bytes before anything has
// vouched for them — inverting the one ordering rule the checkout files are
// built on. This package therefore does the opposite: every key in the set
// is tried against the signature, and the claim is read only after all of
// them have failed, at which point the file is already known not to be
// authentic under any key held and the only remaining question is which
// error to report. The claim picks an error label; it never picks a key,
// and it can never introduce one. See (*LicenseFile).VerifyWithKeySet.
//
// The cost is at most one signature check per key the account has ever
// held — microseconds each for Ed25519, on a set that is realistically a
// handful of entries.
//
// # Ed25519 only, and why that is not a gap
//
// Every key the server publishes is Ed25519: rotation is `rotate_ed25519`
// and inserts a literal 'ed25519' (accounts/signing_keys.rs). A .lic file
// is Ed25519-signed regardless of the licence's own Scheme. A .machine file
// under an RSA or ECDSA scheme is signed with the account's RSA/ECDSA key
// (check_out_machine.rs:86-99) — and those keys are never published here
// and never rotated by anything, so the rotation defect this type exists
// for cannot arise for them. Verify such a file with the existing
// (*MachineFile).Verify and the public key you already hold;
// VerifyWithKeySet reports ErrNoUsableSigningKey rather than pretending
// otherwise.
//
// ⚠️ And note what that means for the claim on such a file: its `kid` names
// the account's ED25519 key even though an RSA or ECDSA key signed the
// bytes, because check_out_machine.rs:127 derives the claim from
// account.ed25519_public_key whatever scheme was actually used. A `kid` on
// a non-Ed25519 machine file is therefore real but useless for key
// selection. Treat `kid` as meaningful for Ed25519-signed files only.
//
// The zero value is a valid empty set, and a nil *SigningKeySet is safe to
// call every method on.
type SigningKeySet struct {
	entries []signingKeyEntry
}

// NewSigningKeySet builds a key set from the account's published keys, as
// returned by (*Client).ListSigningKeys.
//
// Deliberately lenient, and for the opposite reason
// NewSigningKeySetFromPublicKeys is strict: this input is the server's
// whole key history, so one unusable row — a future non-Ed25519 algorithm,
// a legacy key that does not decode to 32 bytes — must not strand every
// file the account has already signed. Such rows are skipped; a file naming
// one then surfaces as an *UnknownSigningKeyError carrying the `kid`, which
// is the honest answer. Compare Len against the number of resources you
// passed in if you need to know something was dropped.
//
// Keys are indexed by the resource's own ID, which IS the `kid` — the
// server writes the same value into the file's claim, so no local hashing
// decides membership on this path. KeyID is still applied as a cross-check:
// a row whose published id disagrees with the id its own public key hashes
// to is kept and matches under EITHER id (so a mislabelled row cannot turn
// an authentic file into a reported forgery) and is listed by Mismatched.
func NewSigningKeySet(keys []SigningKey) *SigningKeySet {
	entries := make([]signingKeyEntry, 0, len(keys))
	for _, key := range keys {
		if key.Attributes.Algorithm != ed25519Algorithm {
			continue
		}
		pub, err := decodeEd25519PublicKey(key.Attributes.PublicKey)
		if err != nil {
			continue
		}
		entries = append(entries, signingKeyEntry{
			key:        key,
			publicKey:  pub,
			computedID: KeyID(key.Attributes.PublicKey),
		})
	}
	return &SigningKeySet{entries: entries}
}

// NewSigningKeySetFromPublicKeys builds a key set from Ed25519 public keys
// the caller already holds, each standard base64 of the raw 32 bytes — the
// form the server publishes and stores.
//
// This is the offline path, and for an embedded client it is usually the
// ONLY path: GET /signing-keys is gated on `account.read`, which the
// LicenseToken role does not hold, so a client built WithLicenseKey gets
// 403 there unconditionally (see (*Client).ListSigningKeys). Pin the
// account's current and previous public keys in the application binary and
// pass them here; verification then survives a rotation that happened
// before the build shipped, with no network access at all.
//
// Strict where NewSigningKeySet is lenient: a key that is not valid base64
// of exactly 32 bytes is an error rather than being skipped. A typo in a
// key pinned in a binary must fail loudly at startup, not silently produce
// a set that reports every genuine file in the field as signed by an
// unknown key.
//
// Each key is indexed by its computed KeyID, since there is no served id on
// this path.
func NewSigningKeySetFromPublicKeys(publicKeysBase64 ...string) (*SigningKeySet, error) {
	entries := make([]signingKeyEntry, 0, len(publicKeysBase64))
	for i, b64 := range publicKeysBase64 {
		pub, err := decodeEd25519PublicKey(b64)
		if err != nil {
			return nil, fmt.Errorf("tamga: signing key %d: %w", i, err)
		}
		kid := KeyID(b64)
		entries = append(entries, signingKeyEntry{
			key: SigningKey{
				ID:   kid,
				Type: "signing-keys",
				Attributes: SigningKeyAttributes{
					Algorithm: ed25519Algorithm,
					PublicKey: b64,
				},
			},
			publicKey:  pub,
			computedID: kid,
		})
	}
	return &SigningKeySet{entries: entries}, nil
}

// decodeEd25519PublicKey decodes standard base64 into a raw 32-byte Ed25519
// public key, rejecting anything that is not exactly that.
func decodeEd25519PublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("tamga: signing key is not valid standard base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("tamga: signing key decodes to %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Len is how many usable keys the set holds — rows skipped by
// NewSigningKeySet are not counted.
func (s *SigningKeySet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

// KeyIDs lists the `kid`s this set can verify against, in the order they
// were supplied. Worth logging next to an *UnknownSigningKeyError to show
// what the set did hold.
func (s *SigningKeySet) KeyIDs() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e.key.ID)
	}
	return out
}

// Keys returns the usable published resources backing this set, in the
// order they were supplied.
func (s *SigningKeySet) Keys() []SigningKey {
	if s == nil {
		return nil
	}
	out := make([]SigningKey, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e.key)
	}
	return out
}

// Find returns the key this set holds under kid.
//
// Matching is exact and case-sensitive — the server emits lowercase hex on
// both sides, in the resource id and in the file's claim alike — and
// accepts either the published id or the id the key's own material hashes
// to. Those are the same string for every key the server has ever
// published; accepting both means a mislabelled row still resolves the
// files it legitimately signed.
func (s *SigningKeySet) Find(kid string) (SigningKey, bool) {
	if e, ok := s.find(kid); ok {
		return e.key, true
	}
	return SigningKey{}, false
}

func (s *SigningKeySet) find(kid string) (signingKeyEntry, bool) {
	if s == nil || kid == "" {
		return signingKeyEntry{}, false
	}
	for _, e := range s.entries {
		if e.key.ID == kid || e.computedID == kid {
			return e, true
		}
	}
	return signingKeyEntry{}, false
}

// Mismatched lists the published ids whose key material does not hash to
// the id the server served it under — i.e. where KeyID(publicKey) != id.
//
// Always empty against a healthy server, and that is the point: this is the
// cross-check on a value the API hands over ready-made, not a second source
// of truth. A non-empty result means the published key set is internally
// inconsistent and offline verification for those ids is running on a
// guess; it is a signal to investigate the account, not a reason to reject
// a file, which is why nothing in this package fails on it.
func (s *SigningKeySet) Mismatched() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, e := range s.entries {
		if e.key.ID != e.computedID {
			out = append(out, e.key.ID)
		}
	}
	return out
}

// Sentinel errors for key-set verification. All three are local, offline
// conditions raised by VerifyWithKeySet — none is an API response — and all
// three are deliberately distinct from ErrInvalidSignature, because
// "authentic file, wrong or missing key" and "this file was tampered with"
// are different incidents that call for opposite responses: refresh keys
// and let the customer in, versus refuse the customer.
var (
	// ErrUnknownSigningKey is returned when a file's `kid` claim names a
	// key the supplied SigningKeySet does not hold.
	//
	// ⚠️ This is NOT a forgery. It is what a genuine file signed before a
	// key rotation produces against a key set that has not caught up — a
	// cached set, or an application shipped with one pinned key. A tampered
	// file whose `kid` IS known fails as ErrInvalidSignature instead.
	//
	// Fetch the key set again ((*Client).GetSigningKeySet) or ship an
	// application update carrying the new public key, then retry. The
	// accompanying *UnknownSigningKeyError carries the claimed `kid` and
	// the ones the set held.
	ErrUnknownSigningKey = errors.New("tamga: no signing key for the kid this file names")

	// ErrSigningKeyNotPublished is the more specific outcome when the
	// claimed `kid` is UnpublishedSigningKeyID: the account that signed the
	// file has no Ed25519 public key at all, so it signed with the id of
	// the empty string.
	//
	// Refreshing the key set will not fix this and retrying will not either
	// — there is no key to fetch. An operator has to rotate one into the
	// account server-side. It does NOT match ErrUnknownSigningKey, so a
	// caller cannot accidentally report "your keys are stale" for a
	// condition no client action can resolve.
	ErrSigningKeyNotPublished = errors.New("tamga: this file names the empty-key id " + UnpublishedSigningKeyID + ": the account that signed it has published no Ed25519 signing key")

	// ErrNoUsableSigningKey is returned when the set holds no key that
	// could verify this file even in principle — an empty set, or a
	// .machine file under an RSA/ECDSA scheme, whose signing key is never
	// published and never rotated (see SigningKeySet).
	//
	// A configuration problem rather than a rotation one: nothing about
	// the file has been judged, because there was nothing to judge it
	// against.
	ErrNoUsableSigningKey = errors.New("tamga: the signing key set holds no key that can verify this file")
)

// UnknownSigningKeyError reports a file whose `kid` claim names no key in
// the set it was verified against, carrying enough detail to tell an
// operator what to do next.
//
// Match the class with errors.Is(err, ErrUnknownSigningKey) — or
// errors.Is(err, ErrSigningKeyNotPublished) for the unpublished-account
// case, which is the same type reporting a different, non-overlapping
// sentinel. Use errors.As to read KeyID and Available.
type UnknownSigningKeyError struct {
	// KeyID is the `kid` the file claims, verbatim and unverified. It came
	// from bytes whose signature did not check out under any key held, so
	// treat it as a diagnostic string and nothing more.
	//
	// It leads the struct only to satisfy govet's fieldalignment check.
	KeyID string
	// Available is the set of `kid`s that were actually held, for a log
	// line next to KeyID.
	Available []string
}

func (e *UnknownSigningKeyError) Error() string {
	if e.KeyID == UnpublishedSigningKeyID {
		return fmt.Sprintf("tamga: this file names the empty-key id %s (the account that signed it has published no Ed25519 signing key); the key set holds %v", e.KeyID, e.Available)
	}
	return fmt.Sprintf("tamga: no signing key for kid %s in the supplied key set; it holds %v", e.KeyID, e.Available)
}

// Unwrap reports the sentinel this instance belongs to, so
// errors.Is(err, ErrUnknownSigningKey) and
// errors.Is(err, ErrSigningKeyNotPublished) each match exactly the cases
// they name and never both.
func (e *UnknownSigningKeyError) Unwrap() error {
	if e.KeyID == UnpublishedSigningKeyID {
		return ErrSigningKeyNotPublished
	}
	return ErrUnknownSigningKey
}

// ListSigningKeys reads every Ed25519 signing key the account has held,
// retired ones included.
// GET /v1/accounts/{account_id}/signing-keys.
//
// The retired keys are the entire point. An offline file names its signer
// with a `kid` claim, and a file issued before the last rotation needs the
// key that signed it, not the current one; without this route a client's
// only options are to fail verification on an authentic file or to accept
// any key, and the second defeats signing altogether.
//
// The returned resources' IDs are `kid`s, not UUIDs — see SigningKey. Feed
// them to NewSigningKeySet, or call (*Client).GetSigningKeySet to do both
// in one step.
//
// ⚠️ NOT callable with a license key. This route authorizes on
// `account.read` (accounts/list_signing_keys.rs, AccountPolicy::can_read),
// and `account.read` is NOT in the LicenseToken role's default permission
// set (authz/mod.rs) — so a client built with WithLicenseKey gets 403
// FORBIDDEN here unconditionally, however the account is configured. That
// is a role gap, not a setting, so nothing an operator can change on the
// licence fixes it. Same shape as GET /policies/{id}, but unlike that one
// there is no equivalent route reachable through a permission the role does
// hold. Two ways round it, both supported here:
//
//  1. pin the public keys in the application binary and build the set with
//     NewSigningKeySetFromPublicKeys — no network, no permission; or
//  2. have the application's own backend call this with a bearer token
//     whose role carries `account.read` and serve the result onward.
func (c *Client) ListSigningKeys(ctx context.Context) ([]SigningKey, error) {
	keys, err := decodeJSONAPI[[]SigningKey](ctx, c, "GET", "/signing-keys", nil)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// GetSigningKeySet reads the account's published signing keys and returns
// them as a SigningKeySet ready to verify through — ListSigningKeys
// followed by NewSigningKeySet.
//
// One call, and the result is worth holding for the life of the process: a
// rotation ADDS a key rather than invalidating the ones already there, so a
// cached set only ever goes stale for files signed after it was fetched —
// which is exactly the condition ErrUnknownSigningKey names, and the signal
// to call this again. There is nothing to poll.
//
//	keys, err := client.GetSigningKeySet(ctx)
//	if err != nil {
//		return err
//	}
//	verified, err := file.VerifyWithKeySet(keys, licenseKey)
//
// Carries the same licence-key restriction as ListSigningKeys — read that
// doc comment before wiring this into an embedded client.
func (c *Client) GetSigningKeySet(ctx context.Context) (*SigningKeySet, error) {
	keys, err := c.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	return NewSigningKeySet(keys), nil
}
