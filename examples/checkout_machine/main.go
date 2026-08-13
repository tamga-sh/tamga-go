// Command checkout_machine demonstrates downloading, verifying, and
// (optionally) decrypting a .machine offline machine file entirely
// offline once downloaded, across all four supported signing schemes
// (checkout_machine.go's Verify dispatches by the caller-supplied
// LicenseScheme, never by parsing the file's own alg string).
//
// Run (pubkey format depends on -scheme — see checkout_machine.go's
// Verify doc comment: raw 32 bytes for Ed25519, SubjectPublicKeyInfo DER
// for either RSA variant, 65-byte uncompressed point for ECDSA):
//
//	go run ./examples/checkout_machine \
//	  -account acct-123 -key lic-abc123 -machine mach-id \
//	  -scheme ED25519_SIGN -pubkey <base64 pubkey> \
//	  [-encrypt -fingerprint this-machine-fingerprint]
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"math/big"

	"github.com/tamga-sh/tamga-go/v2"
)

func main() {
	var (
		accountID   = flag.String("account", "", "Tamga account ID (required)")
		key         = flag.String("key", "", "license key, used both as the auth credential and (if -encrypt) part of the decryption key (required)")
		machineID   = flag.String("machine", "", "machine ID to check out (required)")
		schemeFlag  = flag.String("scheme", string(tamga.SchemeEd25519Sign), "signing scheme: ED25519_SIGN, RSA_2048_PKCS1_SIGN, RSA_2048_PKCS1_PSS_SIGN, or ECDSA_P256_SIGN — must match the governing license's own scheme field, never guessed from the file")
		pubKeyB64   = flag.String("pubkey", "", "base64-encoded public key matching -scheme's format (required)")
		encrypt     = flag.Bool("encrypt", false, "request an AES-256-GCM-encrypted checkout file")
		fingerprint = flag.String("fingerprint", "", "this machine's fingerprint, required if -encrypt is set (machine files need both the license key AND fingerprint to decrypt)")
	)
	flag.Parse()
	if *accountID == "" || *key == "" || *machineID == "" || *pubKeyB64 == "" {
		log.Fatal("usage: checkout_machine -account <account-id> -key <license-key> -machine <machine-id> -scheme <scheme> -pubkey <base64-pubkey> [-encrypt -fingerprint <fp>]")
	}
	scheme := tamga.LicenseScheme(*schemeFlag)

	pubKey, err := parsePublicKey(scheme, *pubKeyB64)
	if err != nil {
		log.Fatalf("parse -pubkey: %v", err)
	}

	client, err := tamga.New(*accountID, tamga.WithLicenseKey(*key))
	if err != nil {
		log.Fatalf("tamga.New: %v", err)
	}
	ctx := context.Background()

	file, err := client.CheckOutMachine(ctx, *machineID, tamga.CheckOutOptions{Encrypt: *encrypt})
	if err != nil {
		log.Fatalf("CheckOutMachine: %v", err)
	}
	fmt.Printf("downloaded .machine file, alg=%s\n", file.Alg)

	licenseKeyForDecrypt, fingerprintForDecrypt := "", ""
	if *encrypt {
		if *fingerprint == "" {
			log.Fatal("-fingerprint is required when -encrypt is set")
		}
		licenseKeyForDecrypt, fingerprintForDecrypt = *key, *fingerprint
	}
	payload, err := file.Verify(scheme, pubKey, licenseKeyForDecrypt, fingerprintForDecrypt)
	if err != nil {
		log.Fatalf("Verify: %v (is -scheme/-pubkey correct for this account's license, and -encrypt/-fingerprint set correctly?)", err)
	}
	fmt.Printf("verified offline: machine fingerprint=%s heartbeat_status=%s\n",
		payload.Data.Attributes.Fingerprint, payload.Data.Attributes.HeartbeatStatus)
}

// parsePublicKey decodes -pubkey per -scheme's documented wire format
// (checkout_machine.go's Verify doc comment): raw 32 bytes for Ed25519, an
// SPKI DER blob for either RSA variant, or a 65-byte uncompressed P-256
// point for ECDSA.
func parsePublicKey(scheme tamga.LicenseScheme, b64 string) (crypto.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	switch scheme {
	case tamga.SchemeEd25519Sign:
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("expected %d raw bytes for Ed25519, got %d", ed25519.PublicKeySize, len(raw))
		}
		return ed25519.PublicKey(raw), nil
	case tamga.SchemeRSA2048PKCS1Sign, tamga.SchemeRSA2048PKCS1PSSSign:
		pub, err := x509.ParsePKIXPublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse SPKI DER: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("SPKI DER did not contain an RSA public key, got %T", pub)
		}
		return rsaPub, nil
	case tamga.SchemeECDSAP256Sign:
		if len(raw) != 65 || raw[0] != 0x04 {
			return nil, fmt.Errorf("expected a 65-byte uncompressed P-256 point (0x04 prefix), got %d bytes", len(raw))
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(raw[1:33]),
			Y:     new(big.Int).SetBytes(raw[33:65]),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported -scheme %q", scheme)
	}
}
