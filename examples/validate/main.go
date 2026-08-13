// Command validate demonstrates ValidateByKey (unscoped) and ValidateByID
// with a populated Scope (product/policy/user/environment).
//
// Run:
//
//	go run ./examples/validate -account acct-123 -key lic-abc123
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/tamga-sh/tamga-go/v2"
)

func main() {
	var (
		accountID = flag.String("account", "", "Tamga account ID (required)")
		key       = flag.String("key", "", "license key to validate (required)")
		baseURL   = flag.String("base-url", "", "override the API base URL (default https://api.tamga.sh)")
	)
	flag.Parse()
	if *accountID == "" || *key == "" {
		log.Fatal("usage: validate -account <account-id> -key <license-key> [-base-url <url>]")
	}

	opts := []tamga.Option{tamga.WithLicenseKey(*key)}
	if *baseURL != "" {
		opts = append(opts, tamga.WithBaseURL(*baseURL))
	}
	client, err := tamga.New(*accountID, opts...)
	if err != nil {
		log.Fatalf("tamga.New: %v", err)
	}

	ctx := context.Background()

	// ValidateByKey: no scope support, simplest way to check a raw key.
	license, meta, err := client.ValidateByKey(ctx, *key)
	if err != nil {
		log.Fatalf("ValidateByKey: %v", err)
	}
	fmt.Printf("ValidateByKey: valid=%v code=%s license_id=%s\n", meta.Valid, meta.Code, license.ID)

	// ValidateByID with a populated Scope: only Product/Policy/User/
	// Environment are actually enforced server-side today (see Scope's
	// doc comment in license.go) — Entitlements/Fingerprint/Version/
	// Checksum are modeled for forward-compatibility only.
	scope := &tamga.Scope{
		Fingerprint: strPtr("this-machine-fingerprint"),
	}
	_, scopedMeta, err := client.ValidateByID(ctx, license.ID, &tamga.ValidateByIDOptions{
		Scope:     scope,
		SkipTouch: true, // polling validity without bumping last_validated_at
	})
	if err != nil {
		log.Fatalf("ValidateByID: %v", err)
	}
	fmt.Printf("ValidateByID: valid=%v code=%s\n", scopedMeta.Valid, scopedMeta.Code)
}

func strPtr(s string) *string { return &s }
