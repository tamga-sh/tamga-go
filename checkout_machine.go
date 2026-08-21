package tamga

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	internalcrypto "github.com/tamga-sh/tamga-go/internal/crypto"
)

const (
	machineFilePEMHeader = "-----BEGIN MACHINE FILE-----"
	machineFilePEMFooter = "-----END MACHINE FILE-----"
)

// maxCheckoutTTLSeconds is the server-validated upper bound for a checkout
// TTL — 365 days (Tamga API protocol specification §6). Both license and
// machine checkout accept a ttl param, but only machine checkout validates
// it server-side; this SDK pre-checks it client-side only for
// CheckOutMachine, mirroring that asymmetry rather than inventing a
// client-side check the server itself doesn't enforce for license checkout.
const maxCheckoutTTLSeconds = 365 * 24 * 3600

// checkTTL mirrors the server's validated ttl range for machine checkout
// (> 0 and <= 31536000 seconds), short-circuiting with ErrTTLInvalid
// before the request is even sent.
func checkTTL(ttl int) error {
	if ttl <= 0 || ttl > maxCheckoutTTLSeconds {
		return fmt.Errorf("%w: must be > 0 and <= %d, got %d", ErrTTLInvalid, maxCheckoutTTLSeconds, ttl)
	}
	return nil
}

// MachineFile is a parsed .machine checkout certificate — same
// {Enc, Sig, Alg} shape as LicenseFile (checkout_license.go), plus the raw
// PEM text and checkout metadata when fetched via the POST variant.
type MachineFile struct {
	Enc string
	Sig string
	Alg string
	PEM string

	// Now overrides the clock Verify uses to check the signed exp claim.
	//
	// Same escape hatch, and the same reason, as (*LicenseFile).Now: on an
	// offline check the local clock belongs to the attacker, so an
	// application that keeps a server-supplied timestamp should pass it
	// here rather than let a user wind the system clock back to revive an
	// expired file. Leave nil to use time.Now().
	Now func() int64

	ID       string
	TTL      *int64
	Expiry   *string
	Issued   string
	Includes []string
}

type machineFileResourceAttrs struct {
	TTL         *int64   `json:"ttl"`
	Expiry      *string  `json:"expiry"`
	Certificate string   `json:"certificate"`
	Algorithm   string   `json:"algorithm"`
	Issued      string   `json:"issued"`
	Includes    []string `json:"includes"`
}

type machineFileResource struct {
	ID         string                   `json:"id"`
	Type       string                   `json:"type"`
	Attributes machineFileResourceAttrs `json:"attributes"`
}

// CheckOutMachine downloads an offline .machine checkout certificate for a
// machine, dispatching to the GET (raw octet-stream PEM) or POST (JSON:API
// machine-files resource) variant per opts.UsePOST. Same encrypt/ttl shape
// as CheckOutLicense (CheckOutOptions), with one machine-specific
// difference: if opts.TTL is set, it is validated client-side (> 0 and
// <= 31536000 seconds) via checkTTL before the request is sent, mirroring
// the server's own validated range and short-circuiting with an error
// matching ErrTTLInvalid instead of round-tripping to find out.
func (c *Client) CheckOutMachine(ctx context.Context, machineID string, opts CheckOutOptions) (*MachineFile, error) {
	if opts.TTL != nil {
		if err := checkTTL(*opts.TTL); err != nil {
			return nil, err
		}
	}
	path := fmt.Sprintf("/machines/%s/actions/check-out", escapePathSegment(machineID))
	if opts.UsePOST {
		return c.checkOutMachinePOST(ctx, path, opts)
	}
	return c.checkOutMachineGET(ctx, path, opts)
}

func (c *Client) checkOutMachineGET(ctx context.Context, path string, opts CheckOutOptions) (*MachineFile, error) {
	query := url.Values{}
	query.Set("encrypt", strconv.FormatBool(opts.Encrypt))
	if opts.TTL != nil {
		query.Set("ttl", strconv.Itoa(*opts.TTL))
	}
	pem, err := doRawText(ctx, c, "GET", path, query)
	if err != nil {
		return nil, err
	}
	return ParseMachineFile(pem)
}

func (c *Client) checkOutMachinePOST(ctx context.Context, path string, opts CheckOutOptions) (*MachineFile, error) {
	meta := map[string]any{"encrypt": opts.Encrypt}
	if opts.TTL != nil {
		meta["ttl"] = *opts.TTL
	} else {
		meta["ttl"] = nil
	}
	body := map[string]any{"meta": meta}
	resource, err := decodeJSONAPI[machineFileResource](ctx, c, "POST", path, body)
	if err != nil {
		return nil, err
	}
	file, err := ParseMachineFile(resource.Attributes.Certificate)
	if err != nil {
		return nil, err
	}
	file.ID = resource.ID
	file.TTL = resource.Attributes.TTL
	file.Expiry = resource.Attributes.Expiry
	file.Issued = resource.Attributes.Issued
	file.Includes = resource.Attributes.Includes
	return file, nil
}

// ParseMachineFile strips the -----BEGIN/END MACHINE FILE----- markers,
// base64-decodes the body, and unmarshals the inner {enc, sig, alg} JSON —
// it does not verify the signature; call (*MachineFile).Verify for that.
func ParseMachineFile(pemText string) (*MachineFile, error) {
	body, err := stripPEM(pemText, machineFilePEMHeader, machineFilePEMFooter)
	if err != nil {
		return nil, err
	}
	certJSON, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in machine file certificate: %w", err)
	}
	var cert certPayload
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		return nil, fmt.Errorf("tamga: invalid JSON in machine file certificate: %w", err)
	}
	return &MachineFile{Enc: cert.Enc, Sig: cert.Sig, Alg: cert.Alg, PEM: pemText}, nil
}

// MachinePayload is the {"data": Machine, "meta": <claims>} payload a
// verified MachineFile decodes to.
type MachinePayload struct {
	// Claims are the signed meta claims the server binds into the signed
	// bytes (check_out_machine.rs builds them from the same
	// LicenseFileClaims type the license-file path uses). Verify has
	// already enforced ExpiresAt by the time a caller sees these; IssuedAt,
	// ID (jti) and KeyID (kid) are exposed for the caller's own use —
	// jti for replay detection, kid for a future key rotation.
	Claims LicenseFileClaims
	Data   Machine
}

// Verify orchestrates the full verify -> decrypt -> parse pipeline for an
// offline .machine file.
//
// scheme MUST come from the governing license's own Scheme field — never
// guessed by parsing f.Alg's suffix, which cannot safely disambiguate
// RSA_2048_PKCS1_SIGN from RSA_2048_JWT_RS256 (both would produce an
// "rsa-sha256"-suffixed alg string server-side); trusting attacker-
// influenced input to select a crypto primitive is an algorithm-confusion
// risk regardless of whether disambiguation happens to be possible. If the
// license has no Scheme set, pass SchemeEd25519Sign — the server's own
// default when generating a machine file for an unset scheme.
//
// pub must be the concrete key type matching scheme: ed25519.PublicKey for
// SchemeEd25519Sign, *rsa.PublicKey for SchemeRSA2048PKCS1Sign/
// SchemeRSA2048PKCS1PSSSign, or *ecdsa.PublicKey for SchemeECDSAP256Sign.
//
// licenseKey/fingerprint are required only for an encrypted
// (aes-256-gcm+...) file — both are needed to re-derive the HKDF key (see
// internal/crypto/hkdf.go); pass "" for a plain file. Needing the
// fingerprint is what binds a machine file to one machine: it cannot be
// opened anywhere else, even with the license key.
//
// A machine file carries the same signed meta claims as a license file —
// check_out_machine.rs builds {"data": .., "meta": LicenseFileClaims} and
// signs the pair — so the signed exp is enforced here exactly as
// (*LicenseFile).Verify enforces its own, with the same
// clockSkewToleranceSeconds allowance and the same *ExpiredError outcome.
// exp is optional by design: a checkout requested with no ttl produces a
// file with no exp that genuinely never expires, so an absent exp is not an
// error. The fingerprint binding still bounds an encrypted file to one
// machine regardless.
//
// ⚠️ SchemeRSA2048JWTRS256 is rejected up front — before any parsing or
// crypto primitive is invoked — with an error matching ErrSchemeNotSupported,
// mirroring the server's own 422 SCHEME_NOT_SUPPORTED for this scheme
// specifically. Reuses the same "sign over the base64 string, not decoded
// bytes" convention as checkout_license.go — see that file's Verify doc
// comment for the gotcha this shares.
func (f *MachineFile) Verify(scheme LicenseScheme, pub crypto.PublicKey, licenseKey, fingerprint string) (*MachinePayload, error) {
	if scheme == SchemeRSA2048JWTRS256 {
		return nil, ErrSchemeNotSupported
	}

	// Alg parse + suffix cross-check (defense in depth): the file's own
	// alg string must be a well-formed v2 "<encoding>+<suffix>+v2" triple
	// declaring the suffix expected for the caller-supplied scheme, e.g.
	// "base64+ed25519+v2" for SchemeEd25519Sign. This never substitutes
	// for the scheme parameter itself as the source of truth (see Verify's
	// doc comment for why alg's suffix alone can't safely disambiguate
	// RSA_2048_PKCS1_SIGN from RSA_2048_JWT_RS256) — it only catches a
	// caller passing a scheme that doesn't match the file it actually
	// downloaded, before any crypto primitive runs.
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

	sigBytes, err := base64.StdEncoding.DecodeString(f.Sig)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in machine file signature: %w", err)
	}

	verified, err := verifyMachineFileSignature(scheme, pub, []byte(f.Enc), sigBytes)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, ErrInvalidSignature
	}

	// Only now, with the signature checked, is enc decoded. Which decoding
	// applies is decided by the encoding prefix parsed out of the (signed-
	// over, cross-checked) alg string — never by sniffing enc itself for a
	// dot, which would let the file's own body pick its parser.
	var plaintext []byte
	switch encPrefix {
	case "base64":
		plaintext, err = base64.StdEncoding.DecodeString(f.Enc)
		if err != nil {
			return nil, fmt.Errorf("tamga: invalid base64 in machine file enc: %w", err)
		}
	case "aes-256-gcm":
		if licenseKey == "" {
			return nil, ErrLicenseKeyRequired
		}
		if fingerprint == "" {
			return nil, ErrFingerprintRequired
		}
		nonce, ciphertextAndTag, splitErr := splitEncryptedEnc(f.Enc)
		if splitErr != nil {
			return nil, splitErr
		}
		key, keyErr := internalcrypto.DeriveMachineFileKey(licenseKey, fingerprint)
		if keyErr != nil {
			return nil, keyErr
		}
		plaintext, err = internalcrypto.OpenAESGCM(key, nonce, ciphertextAndTag)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("tamga: unsupported machine file algorithm prefix %q", encPrefix)
	}

	var payload dataPayload[Machine]
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("tamga: invalid JSON in decoded machine file payload: %w", err)
	}

	// Same second line behind the alg gate as the license-file path: a v2
	// file always carries meta (check_out_machine.rs builds it
	// unconditionally), so reaching the expiry check with nothing to check
	// means the file is not what its own +v2 marker claims.
	if payload.Meta == nil {
		return nil, fmt.Errorf("tamga: machine file payload is missing the signed meta claims: %w", ErrMissingClaims)
	}

	// The signature proves the file is authentic. It does not prove it is
	// still valid — that is this check. exp is optional server-side
	// (check_out_machine.rs sets it to ttl.map(..)), so a file checked out
	// with no ttl has no exp and never expires; that absence is legitimate
	// and is not an error.
	if payload.Meta.ExpiresAt != 0 {
		if f.now()-clockSkewToleranceSeconds > payload.Meta.ExpiresAt {
			return nil, &ExpiredError{ExpiresAt: payload.Meta.ExpiresAt}
		}
	}

	return &MachinePayload{Data: payload.Data, Claims: *payload.Meta}, nil
}

// now returns the current Unix timestamp, or the injected one — same
// contract as (*LicenseFile).now, see that method for why the override
// exists.
func (f *MachineFile) now() int64 {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now().Unix()
}

// machineFileAlgV2Marker is the trailing format-version marker every
// server-issued machine file carries: machine_file_alg_str formats
// "<encoding>+<signing suffix>+v2".
const machineFileAlgV2Marker = "v2"

// parseMachineFileAlg splits a machine file's alg string into its encoding
// prefix and signing suffix, rejecting anything that does not carry the v2
// marker.
//
// Both halves can contain the hyphen the segments are otherwise built from
// ("aes-256-gcm", "rsa-pss-sha256"), so the split is anchored on the FIRST
// and LAST "+" and never on a hyphen or a fixed segment index. An equality
// test against the whole post-first-"+" remainder is what was wrong here
// before: "base64+ed25519+v2" left "ed25519+v2", which never equals
// "ed25519", so every file the server actually issues was rejected.
//
// A file with no "+v2" is refused rather than tolerated. A v1 file carried
// no meta.exp inside the signed payload and derived its AES key by
// zero-padding the license key instead of through HKDF; accepting one
// silently reinstates both weaknesses (see AlgBase64Ed25519's comment in
// checkout_license.go for the same rule on the license side). A substring
// "contains v2" test is not equivalent — it also accepts
// "base64+ed25519+v3" and "base64+ed25519+v2junk".
func parseMachineFileAlg(alg string) (encPrefix, signSuffix string, err error) {
	encPrefix, rest, ok := strings.Cut(alg, "+")
	if !ok {
		return "", "", fmt.Errorf("tamga: unsupported machine file algorithm %q", alg)
	}
	sep := strings.LastIndex(rest, "+")
	if sep < 0 {
		return "", "", fmt.Errorf("tamga: machine file algorithm %q has no +%s format marker (pre-v2 file)", alg, machineFileAlgV2Marker)
	}
	signSuffix, marker := rest[:sep], rest[sep+1:]
	if marker != machineFileAlgV2Marker {
		return "", "", fmt.Errorf("tamga: machine file algorithm %q has no +%s format marker (pre-v2 file)", alg, machineFileAlgV2Marker)
	}
	if encPrefix == "" || signSuffix == "" {
		return "", "", fmt.Errorf("tamga: unsupported machine file algorithm %q", alg)
	}
	return encPrefix, signSuffix, nil
}

// splitEncryptedEnc splits an encrypted machine file's enc field into its
// nonce and ciphertext||tag halves and base64-decodes each.
//
// ⚠️ An encrypted machine file's enc is "<nonce_b64>.<cipher_b64>" — two
// SEPARATELY base64-encoded halves joined by a dot, produced by the
// server's FieldEncryption::encrypt. It is NOT base64(nonce||ciphertext||
// tag): decoding the whole string as one blob and slicing 12 bytes off the
// front is wrong, and in Go fails outright because
// base64.StdEncoding.DecodeString rejects the ".". The server's own doc
// comment on encode_machine_file still describes the single-blob form and
// is stale — the code beside it (field_encryption.rs, pinned by its
// encrypt_produces_dot_separated_format test) is authoritative.
//
// A license file's enc really is a single base64 blob (encode_license_file
// base64s nonce||ciphertext||tag itself), so checkout_license.go's decode
// is correct as written and must not be "fixed" to match this.
//
// Only ever called after the signature over the whole enc STRING has
// already passed.
func splitEncryptedEnc(enc string) (nonce, ciphertextAndTag []byte, err error) {
	nonceB64, cipherB64, ok := strings.Cut(enc, ".")
	if !ok {
		return nil, nil, fmt.Errorf("tamga: encrypted machine file enc is not in <nonce>.<ciphertext> form")
	}
	if strings.Contains(cipherB64, ".") {
		return nil, nil, fmt.Errorf("tamga: encrypted machine file enc has more than one \".\" separator")
	}
	nonce, err = base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, nil, fmt.Errorf("tamga: invalid base64 in machine file enc nonce: %w", err)
	}
	ciphertextAndTag, err = base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, nil, fmt.Errorf("tamga: invalid base64 in machine file enc ciphertext: %w", err)
	}
	// The 16-byte GCM tag is already appended to the ciphertext half
	// (field_encryption.rs seals in place and appends). OpenAESGCM checks
	// the nonce length itself; this only catches a ciphertext half too
	// short to even hold a tag, so the failure reads as "malformed" rather
	// than as an authentication failure.
	const gcmTagSize = 16
	if len(ciphertextAndTag) < gcmTagSize {
		return nil, nil, fmt.Errorf("tamga: encrypted machine file ciphertext too short (%d bytes)", len(ciphertextAndTag))
	}
	return nonce, ciphertextAndTag, nil
}

// schemeAlgSuffix maps a LicenseScheme to its expected alg suffix, per the
// server's own scheme-to-alg-suffix mapping. Note both SchemeRSA2048PKCS1Sign
// and SchemeRSA2048JWTRS256 map to the same "rsa-sha256" suffix
// server-side — exactly why algorithm selection in Verify is driven by the
// caller-supplied scheme parameter, never by parsing the file's
// self-declared alg string: a self-declared string can't disambiguate
// those two schemes, and trusting untrusted input to select a crypto
// primitive is an algorithm-confusion risk regardless. SchemeRSA2048JWTRS256
// itself never reaches here — Verify rejects it before this cross-check
// runs — but is still mapped for completeness/documentation.
func schemeAlgSuffix(scheme LicenseScheme) (string, error) {
	switch scheme {
	case SchemeEd25519Sign:
		return "ed25519", nil
	case SchemeRSA2048PKCS1Sign, SchemeRSA2048JWTRS256:
		return "rsa-sha256", nil
	case SchemeRSA2048PKCS1PSSSign:
		return "rsa-pss-sha256", nil
	case SchemeECDSAP256Sign:
		return "ecdsa-p256", nil
	default:
		return "", fmt.Errorf("tamga: unrecognized license scheme %q", scheme)
	}
}

// verifyMachineFileSignature dispatches to the algorithm-specific
// verifier for scheme, returning (false, nil) — not an error — for an
// ordinary signature-verification failure (wrong key, tampered message),
// versus a non-nil error only for a structurally wrong pub type (including
// a typed-nil pointer, explicitly guarded below since a nil *rsa.PublicKey/
// *ecdsa.PublicKey would otherwise pass its type assertion and panic
// inside the stdlib verifier) or an already-rejected scheme (defensive:
// Verify already rejects SchemeRSA2048JWTRS256 before calling this).
func verifyMachineFileSignature(scheme LicenseScheme, pub crypto.PublicKey, message, sig []byte) (bool, error) {
	switch scheme {
	case SchemeEd25519Sign:
		pubKey, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false, fmt.Errorf("tamga: Verify: scheme %s requires an ed25519.PublicKey, got %T", scheme, pub)
		}
		return internalcrypto.VerifyEd25519(pubKey, message, sig), nil
	case SchemeRSA2048PKCS1Sign:
		pubKey, ok := pub.(*rsa.PublicKey)
		if !ok || pubKey == nil {
			return false, fmt.Errorf("tamga: Verify: scheme %s requires a non-nil *rsa.PublicKey, got %T", scheme, pub)
		}
		return internalcrypto.VerifyRSAPKCS1v15(pubKey, message, sig) == nil, nil
	case SchemeRSA2048PKCS1PSSSign:
		pubKey, ok := pub.(*rsa.PublicKey)
		if !ok || pubKey == nil {
			return false, fmt.Errorf("tamga: Verify: scheme %s requires a non-nil *rsa.PublicKey, got %T", scheme, pub)
		}
		return internalcrypto.VerifyRSAPSS(pubKey, message, sig) == nil, nil
	case SchemeECDSAP256Sign:
		pubKey, ok := pub.(*ecdsa.PublicKey)
		if !ok || pubKey == nil {
			return false, fmt.Errorf("tamga: Verify: scheme %s requires a non-nil *ecdsa.PublicKey, got %T", scheme, pub)
		}
		return internalcrypto.VerifyECDSA(pubKey, message, sig), nil
	case SchemeRSA2048JWTRS256:
		// Unreachable: Verify rejects this scheme before calling here.
		// Defensive typed error (not a panic) so a future refactor that
		// moves or conditions that early rejection fails safe rather than
		// panicking on attacker-controlled input.
		return false, ErrSchemeNotSupported
	default:
		return false, fmt.Errorf("tamga: unrecognized license scheme %q", scheme)
	}
}

// ParsePKIXPublicKey is a re-export of x509.ParsePKIXPublicKey, for callers
// that already hold a SubjectPublicKeyInfo (SPKI) DER blob and would
// otherwise import crypto/x509 purely for this one call.
//
// ⚠️ It is SPKI-only, and the Tamga API does not publish every account key
// as SPKI — so this is a convenience for keys you already know to be SPKI,
// not a general-purpose loader for (*MachineFile).Verify. Specifically:
//
//   - An ECDSA P-256 account key is a raw 65-byte uncompressed SEC1 point
//     (0x04 || X || Y), not a DER structure at all. This function cannot
//     read it and neither can any other crypto/x509 entry point; build the
//     *ecdsa.PublicKey directly from the coordinates instead (see
//     examples/checkout_machine for the eight lines that does).
//   - An RSA-2048 account key may arrive as PKCS#1 RSAPublicKey DER (270
//     bytes) or as SPKI (294 bytes), depending on which endpoint served it.
//     Use x509.ParsePKCS1PublicKey for the first; only the second parses
//     here.
//   - An Ed25519 account key is the raw 32 bytes; convert with
//     ed25519.PublicKey(b).
//
// Verify itself takes the parsed key, so it is unaffected by any of this —
// the encoding is entirely the caller's side of the boundary.
func ParsePKIXPublicKey(der []byte) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(der)
}
