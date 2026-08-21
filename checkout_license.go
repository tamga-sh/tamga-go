package tamga

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	internalcrypto "github.com/tamga-sh/tamga-go/internal/crypto"
)

// CheckOutOptions configures CheckOutLicense and CheckOutMachine.
type CheckOutOptions struct {
	TTL     *int
	Encrypt bool
	UsePOST bool
}

// LicenseFile is a parsed .lic checkout certificate: the {Enc, Sig, Alg}
// fields from its inner JSON payload, plus the raw PEM text it was parsed
// from. Call Verify to check the signature (and decrypt, if encrypted).
type LicenseFile struct {
	TTL      *int64
	Expiry   *string
	Now      func() int64
	Enc      string
	Sig      string
	Alg      string
	PEM      string
	ID       string
	Issued   string
	Includes []string
}

// Algorithm constants for LicenseFile.Alg — Ed25519 only for the license
// checkout signature, independent of the license's own key Scheme (unlike
// machine checkout in checkout_machine.go, which is scheme-driven).
//
// The +v2 suffix is load-bearing. In v1 the ttl/expiry a caller asked for
// lived only in the JSON:API envelope around the certificate, never inside
// the signed bytes — so a 24-hour trial file was cryptographically valid
// forever, because the client is the attacker and any check built on the
// envelope is bypassed by keeping (or redistributing) the raw certificate
// string. v2 moves the claims inside the signature. Accepting a v1 file would
// hand that back, so Verify rejects one outright.
const (
	AlgBase64Ed25519    = "base64+ed25519+v2"
	AlgAES256GCMEd25519 = "aes-256-gcm+ed25519+v2"
)

// clockSkewToleranceSeconds is how much clock skew Verify tolerates when
// checking exp.
//
// Deliberately small: the client's clock is under the attacker's control, so a
// generous allowance is just a free extension on every expired file. This
// covers ordinary NTP drift and nothing more.
const clockSkewToleranceSeconds = 60

const (
	licenseFilePEMHeader = "-----BEGIN LICENSE FILE-----"
	licenseFilePEMFooter = "-----END LICENSE FILE-----"
)

// certPayload is the inner {enc, sig, alg} JSON payload wrapped by the PEM
// envelope, shared shape between license and machine checkout files.
type certPayload struct {
	Enc string `json:"enc"`
	Sig string `json:"sig"`
	Alg string `json:"alg"`
}

// dataPayload is what enc decodes/decrypts to:
// {"data": <resource>, "meta": <claims>}.
type dataPayload[T any] struct {
	Data T                  `json:"data"`
	Meta *LicenseFileClaims `json:"meta"`
}

// LicenseFileClaims are the claims carried inside the signed bytes.
//
// These are the point of format v2: unlike the response envelope, they cannot
// be edited by whoever holds the file.
type LicenseFileClaims struct {
	ID        string `json:"jti"`
	KeyID     string `json:"kid"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// licenseFileResourceAttrs is the license-files JSON:API resource
// attribute bag returned by the POST checkout variant:
// {certificate, algorithm, includes, ttl, expiry, issued}. includes is
// always [] server-side today — there is no working include[] param
// despite the field existing; don't build an "embedded relationships"
// checkout feature around it.
type licenseFileResourceAttrs struct {
	TTL         *int64   `json:"ttl"`
	Expiry      *string  `json:"expiry"`
	Certificate string   `json:"certificate"`
	Algorithm   string   `json:"algorithm"`
	Issued      string   `json:"issued"`
	Includes    []string `json:"includes"`
}

type licenseFileResource struct {
	ID         string                   `json:"id"`
	Type       string                   `json:"type"`
	Attributes licenseFileResourceAttrs `json:"attributes"`
}

// CheckOutLicense downloads an offline .lic checkout certificate for a
// license, dispatching to the GET (raw octet-stream PEM) or POST
// (JSON:API license-files resource) variant per opts.UsePOST.
//
// The checkout id is a fresh UUIDv7 per call, not idempotent — calling
// checkout twice yields two different certificates (a different signature
// nonce for the encrypted variant).
func (c *Client) CheckOutLicense(ctx context.Context, licenseID string, opts CheckOutOptions) (*LicenseFile, error) {
	path := fmt.Sprintf("/licenses/%s/actions/check-out", escapePathSegment(licenseID))
	if opts.UsePOST {
		return c.checkOutLicensePOST(ctx, path, opts)
	}
	return c.checkOutLicenseGET(ctx, path, opts)
}

func (c *Client) checkOutLicenseGET(ctx context.Context, path string, opts CheckOutOptions) (*LicenseFile, error) {
	query := url.Values{}
	query.Set("encrypt", strconv.FormatBool(opts.Encrypt))
	if opts.TTL != nil {
		query.Set("ttl", strconv.Itoa(*opts.TTL))
	}
	pem, err := doRawText(ctx, c, "GET", path, query)
	if err != nil {
		return nil, err
	}
	return ParseLicenseFile(pem)
}

func (c *Client) checkOutLicensePOST(ctx context.Context, path string, opts CheckOutOptions) (*LicenseFile, error) {
	meta := map[string]any{"encrypt": opts.Encrypt}
	if opts.TTL != nil {
		meta["ttl"] = *opts.TTL
	} else {
		meta["ttl"] = nil
	}
	body := map[string]any{"meta": meta}
	resource, err := decodeJSONAPI[licenseFileResource](ctx, c, "POST", path, body)
	if err != nil {
		return nil, err
	}
	file, err := ParseLicenseFile(resource.Attributes.Certificate)
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

// ParseLicenseFile strips the -----BEGIN/END LICENSE FILE----- markers,
// base64-decodes the body, and unmarshals the inner {enc, sig, alg} JSON —
// it does not verify the signature; call (*LicenseFile).Verify for that.
func ParseLicenseFile(pemText string) (*LicenseFile, error) {
	body, err := stripPEM(pemText, licenseFilePEMHeader, licenseFilePEMFooter)
	if err != nil {
		return nil, err
	}
	certJSON, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in license file certificate: %w", err)
	}
	var cert certPayload
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		return nil, fmt.Errorf("tamga: invalid JSON in license file certificate: %w", err)
	}
	return &LicenseFile{Enc: cert.Enc, Sig: cert.Sig, Alg: cert.Alg, PEM: pemText}, nil
}

// stripPEM trims whitespace and the given header/footer markers from pem,
// returning the base64 body between them.
func stripPEM(pem, header, footer string) (string, error) {
	trimmed := strings.TrimSpace(pem)
	rest, ok := strings.CutPrefix(trimmed, header)
	if !ok {
		return "", fmt.Errorf("tamga: malformed PEM envelope: missing %q header", header)
	}
	body, ok := strings.CutSuffix(rest, footer)
	if !ok {
		return "", fmt.Errorf("tamga: malformed PEM envelope: missing %q footer", footer)
	}
	return strings.TrimSpace(body), nil
}

// LicensePayload is the {"data": License} payload a verified LicenseFile
// decodes to.
type LicensePayload struct {
	Claims LicenseFileClaims
	Data   License
}

// Verify orchestrates the full verify -> decrypt -> parse pipeline for an
// offline .lic file, using pub (the account's Ed25519 public key) to check
// the signature. licenseKey is required only for the encrypted
// AlgAES256GCMEd25519 variant — pass "" for a plain AlgBase64Ed25519 file.
//
// Only format-v2 files are accepted. A payload with no signed meta claims
// is a pre-v2 file and is rejected with ErrMissingClaims; there is no
// fallback path. Once the signature passes, the signed exp claim is
// enforced with a clockSkewToleranceSeconds allowance, returning an
// *ExpiredError (distinct from ErrInvalidSignature so callers can tell an
// ended trial from a forgery).
//
// Verification order matters and is deliberately fail-closed: the
// signature is checked BEFORE enc is base64-decoded, decrypted, or parsed
// as JSON in any way — an attacker-controlled file never reaches any
// decoding/decryption/JSON-parsing step without first passing signature
// verification.
//
// ⚠️ THE CENTRAL GOTCHA OF THIS FILE: the Ed25519 signature covers f.Enc's
// ASCII/UTF-8 bytes — the base64 STRING itself, NOT f.Enc's decoded
// bytes. Get this backwards and every signature check silently fails
// against real server-issued files while still passing against a
// self-generated test fixture that repeats the same mistake (see
// checkout_license_test.go's dedicated regression test for exactly this).
func (f *LicenseFile) Verify(pub ed25519.PublicKey, licenseKey string) (*LicensePayload, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(f.Sig)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in license file signature: %w", err)
	}

	// Step 1: verify the signature over enc's base64 STRING bytes — see
	// the gotcha documented above. Nothing past this point runs against
	// unverified input.
	if !internalcrypto.VerifyEd25519(pub, []byte(f.Enc), sigBytes) {
		return nil, ErrInvalidSignature
	}

	// Step 2: only now, after the signature has passed, decode enc.
	encBytes, err := base64.StdEncoding.DecodeString(f.Enc)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in license file enc: %w", err)
	}

	var plaintext []byte
	switch f.Alg {
	case AlgBase64Ed25519:
		plaintext = encBytes
	case AlgAES256GCMEd25519:
		if licenseKey == "" {
			return nil, ErrLicenseKeyRequired
		}
		key, kerr := internalcrypto.DeriveLicenseFileKey(licenseKey)
		if kerr != nil {
			return nil, kerr
		}
		const nonceSize = 12
		const tagSize = 16
		if len(encBytes) < nonceSize+tagSize {
			return nil, fmt.Errorf("tamga: encrypted license file payload too short (%d bytes)", len(encBytes))
		}
		nonce, ciphertextAndTag := encBytes[:nonceSize], encBytes[nonceSize:]
		plaintext, err = internalcrypto.OpenAESGCM(key, nonce, ciphertextAndTag)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("tamga: unsupported license file algorithm %q", f.Alg)
	}

	var payload dataPayload[License]
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("tamga: invalid JSON in decoded license file payload: %w", err)
	}

	// Second line behind the Alg gate: a file must not reach the expiry check
	// with nothing to check.
	if payload.Meta == nil {
		return nil, ErrMissingClaims
	}

	// The signature proves the file is authentic. It does not prove it is still
	// valid — that is this check, and skipping it is what made v1 files
	// permanent.
	if payload.Meta.ExpiresAt != 0 {
		if f.now()-clockSkewToleranceSeconds > payload.Meta.ExpiresAt {
			return nil, &ExpiredError{ExpiresAt: payload.Meta.ExpiresAt}
		}
	}

	return &LicensePayload{Data: payload.Data, Claims: *payload.Meta}, nil
}

// now returns the current Unix timestamp, or the injected one.
//
// Overridable so tests are deterministic, and so an application that keeps a
// server-supplied timestamp — the recommended defence against a user winding
// the system clock back to revive an expired file — can pass that instead of
// trusting the local clock.
func (f *LicenseFile) now() int64 {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now().Unix()
}

// ErrMissingClaims is returned when a checkout file's payload has no signed
// meta claims — i.e. it is a pre-v2 file. Returned bare by both
// (*LicenseFile).Verify and (*MachineFile).Verify, so its message names no
// file type: the caller knows which one it called, and naming one here made
// the machine-file message contradict itself.
var ErrMissingClaims = errors.New("tamga: checkout file payload is missing the signed meta claims (pre-v2 file)")

// ExpiredError is returned when a checkout file's signature verified but its
// signed exp claim has passed. Both (*LicenseFile).Verify and
// (*MachineFile).Verify return it, with the same
// clockSkewToleranceSeconds allowance, so a caller handles offline expiry
// in one place regardless of which file type it holds.
//
// Its own type on purpose: a caller that cannot tell "expired" from "forged"
// either warns the user about tampering when their trial merely ended, or
// treats a forgery as a renewal prompt.
type ExpiredError struct {
	// ExpiresAt is the exp claim, seconds since the Unix epoch.
	ExpiresAt int64
}

func (e *ExpiredError) Error() string {
	return fmt.Sprintf("tamga: license file expired at unix timestamp %d", e.ExpiresAt)
}

// ErrInvalidSignature is returned by (*LicenseFile).Verify and
// (*MachineFile).Verify when Ed25519/RSA/ECDSA signature verification
// fails, before any decode/decrypt of the payload is attempted.
var ErrInvalidSignature = errors.New("tamga: invalid signature")
