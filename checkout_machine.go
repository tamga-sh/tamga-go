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

	internalcrypto "github.com/tamga-sh/tamga-go/internal/crypto"
)

const (
	machineFilePEMHeader = "-----BEGIN MACHINE FILE-----"
	machineFilePEMFooter = "-----END MACHINE FILE-----"
)

// maxCheckoutTTLSeconds is the server-validated upper bound for a checkout
// TTL — 365 days (docs/sdk.md §6). Both license and machine checkout
// accept a ttl param, but only machine checkout validates it server-side;
// this SDK pre-checks it client-side only for CheckOutMachine, mirroring
// that asymmetry rather than inventing a client-side check the server
// itself doesn't enforce for license checkout.
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

// MachinePayload is the {"data": Machine} payload a verified MachineFile
// decodes to.
type MachinePayload struct {
	Data Machine
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
// internal/crypto/hkdf.go); pass "" for a plain file.
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

	// Alg suffix cross-check (defense in depth): the file's own alg
	// string must declare the suffix expected for the caller-supplied
	// scheme, e.g. "base64+ed25519" for SchemeEd25519Sign. This never
	// substitutes for the scheme parameter itself as the source of truth
	// (see Verify's doc comment for why alg's suffix alone can't safely
	// disambiguate RSA_2048_PKCS1_SIGN from RSA_2048_JWT_RS256) — it only
	// catches a caller passing a scheme that doesn't match the file it
	// actually downloaded, before any crypto primitive runs.
	encPrefix, algSuffix, ok := strings.Cut(f.Alg, "+")
	if !ok {
		return nil, fmt.Errorf("tamga: unsupported machine file algorithm %q", f.Alg)
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

	encBytes, err := base64.StdEncoding.DecodeString(f.Enc)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in machine file enc: %w", err)
	}

	var plaintext []byte
	switch encPrefix {
	case "base64":
		plaintext = encBytes
	case "aes-256-gcm":
		if licenseKey == "" {
			return nil, ErrLicenseKeyRequired
		}
		if fingerprint == "" {
			return nil, ErrFingerprintRequired
		}
		key, err := internalcrypto.DeriveMachineFileKey(licenseKey, fingerprint)
		if err != nil {
			return nil, err
		}
		const nonceSize = 12
		const tagSize = 16
		if len(encBytes) < nonceSize+tagSize {
			return nil, fmt.Errorf("tamga: encrypted machine file payload too short (%d bytes)", len(encBytes))
		}
		nonce, ciphertextAndTag := encBytes[:nonceSize], encBytes[nonceSize:]
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
	return &MachinePayload{Data: payload.Data}, nil
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

// ParsePKIXPublicKey is a re-export of x509.ParsePKIXPublicKey for
// convenience — callers loading an RSA/ECDSA public key for
// (*MachineFile).Verify from a SubjectPublicKeyInfo (SPKI) DER blob (the
// format an account's public key is typically distributed in) can use this
// instead of importing crypto/x509 themselves purely for this one call.
func ParsePKIXPublicKey(der []byte) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(der)
}
