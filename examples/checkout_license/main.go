// Command checkout_license demonstrates downloading, verifying, and
// (optionally) decrypting a .lic offline license file entirely offline
// once downloaded — see checkout_license.go's Verify doc comment for the
// base64-string-vs-decoded-bytes signing gotcha this implements correctly.
//
// Run:
//
//	go run ./examples/checkout_license \
//	  -account acct-123 -key lic-abc123 -license lic-id \
//	  -pubkey <base64 32-byte Ed25519 public key> \
//	  [-encrypt]
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"

	"github.com/tamga-sh/tamga-go/v2"
)

func main() {
	var (
		accountID = flag.String("account", "", "Tamga account ID (required)")
		key       = flag.String("key", "", "license key, used both as the auth credential and (if -encrypt) the decryption key (required)")
		licenseID = flag.String("license", "", "license ID to check out (required)")
		pubKeyB64 = flag.String("pubkey", "", "base64-encoded 32-byte Ed25519 public key for this account (required)")
		encrypt   = flag.Bool("encrypt", false, "request an AES-256-GCM-encrypted checkout file")
	)
	flag.Parse()
	if *accountID == "" || *key == "" || *licenseID == "" || *pubKeyB64 == "" {
		log.Fatal("usage: checkout_license -account <account-id> -key <license-key> -license <license-id> -pubkey <base64-pubkey> [-encrypt]")
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(*pubKeyB64)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		log.Fatalf("-pubkey must be a base64-encoded 32-byte Ed25519 public key: %v", err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	client, err := tamga.New(*accountID, tamga.WithLicenseKey(*key))
	if err != nil {
		log.Fatalf("tamga.New: %v", err)
	}
	ctx := context.Background()

	// Downloads a fresh, non-idempotent certificate — every call yields a
	// different signature nonce for the encrypted variant.
	file, err := client.CheckOutLicense(ctx, *licenseID, tamga.CheckOutOptions{Encrypt: *encrypt})
	if err != nil {
		log.Fatalf("CheckOutLicense: %v", err)
	}
	fmt.Printf("downloaded .lic file, alg=%s\n", file.Alg)

	// Verify + decrypt fully offline — no further network access needed
	// from this point on. licenseKey is only used for the encrypted
	// (aes-256-gcm+ed25519) variant; pass "" for a plain file.
	licenseKeyForDecrypt := ""
	if *encrypt {
		licenseKeyForDecrypt = *key
	}
	payload, err := file.Verify(pubKey, licenseKeyForDecrypt)
	if err != nil {
		log.Fatalf("Verify: %v (is -pubkey correct for this account, and -encrypt set correctly for this file?)", err)
	}
	fmt.Printf("verified offline: license status=%s key=%v\n", payload.Data.Attributes.Status, payload.Data.Attributes.Key)
}
