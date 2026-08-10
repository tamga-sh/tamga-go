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
	Enc string
	Sig string
	Alg string
	PEM string

	// Certificate metadata, populated only when fetched via the POST
	// (UsePOST) variant — zero-valued for the raw GET/ParseLicenseFile
	// path, which has no JSON:API resource wrapper to read them from.
	ID       string
	TTL      *int64
	Expiry   *string
	Issued   string
	Includes []string
}

// Algorithm constants for LicenseFile.Alg — Ed25519 only for the license
// checkout signature, independent of the license's own key Scheme (unlike
// machine checkout in checkout_machine.go, which is scheme-driven).
const (
	AlgBase64Ed25519    = "base64+ed25519"
	AlgAES256GCMEd25519 = "aes-256-gcm+ed25519"
)

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

// dataPayload is what enc decodes/decrypts to: {"data": <resource>}.
type dataPayload[T any] struct {
	Data T `json:"data"`
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
	Data License
}

// Verify orchestrates the full verify -> decrypt -> parse pipeline for an
// offline .lic file, using pub (the account's Ed25519 public key) to check
// the signature. licenseKey is required only for the encrypted
// (aes-256-gcm+ed25519) variant — pass "" for a plain (base64+ed25519)
// file.
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
		key := internalcrypto.DeriveLicenseFileKey(licenseKey)
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
	return &LicensePayload{Data: payload.Data}, nil
}

// ErrInvalidSignature is returned by (*LicenseFile).Verify and
// (*MachineFile).Verify when Ed25519/RSA/ECDSA signature verification
// fails, before any decode/decrypt of the payload is attempted.
var ErrInvalidSignature = errors.New("tamga: invalid signature")
