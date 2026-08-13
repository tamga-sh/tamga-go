// Command entitlements demonstrates HasEntitlement, which matches on the
// entitlement's stable Code — never its Name, which is a display label
// only and may collide with another entitlement's Code (see
// entitlement.go's doc comment).
//
// Run:
//
//	go run ./examples/entitlements -account acct-123 -key lic-abc123 -license lic-id -code pro-features
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/tamga-sh/tamga-go"
)

func main() {
	var (
		accountID = flag.String("account", "", "Tamga account ID (required)")
		key       = flag.String("key", "", "license key (required)")
		licenseID = flag.String("license", "", "license ID to check entitlements for (required)")
		code      = flag.String("code", "", "entitlement code to check for (required)")
	)
	flag.Parse()
	if *accountID == "" || *key == "" || *licenseID == "" || *code == "" {
		log.Fatal("usage: entitlements -account <account-id> -key <license-key> -license <license-id> -code <entitlement-code>")
	}

	client, err := tamga.New(*accountID, tamga.WithLicenseKey(*key))
	if err != nil {
		log.Fatalf("tamga.New: %v", err)
	}
	ctx := context.Background()

	// First call fetches and caches the license's entitlement list (TTL
	// cache, see entitlement.go); a second call for the same license
	// within the TTL reuses the cache instead of making another request.
	has, err := client.HasEntitlement(ctx, *licenseID, *code)
	if err != nil {
		log.Fatalf("HasEntitlement: %v", err)
	}
	if has {
		fmt.Printf("license %s has entitlement %q\n", *licenseID, *code)
	} else {
		fmt.Printf("license %s does NOT have entitlement %q\n", *licenseID, *code)
	}

	// For the full list (e.g. to display all entitlements in a UI),
	// paginate with ListEntitlements directly instead.
	page, err := client.ListEntitlements(ctx, *licenseID, tamga.ListOptions{Limit: 100})
	if err != nil {
		log.Fatalf("ListEntitlements: %v", err)
	}
	fmt.Printf("license has %d entitlement(s):\n", len(page.Items))
	for _, e := range page.Items {
		fmt.Printf("  - %s (code=%s)\n", e.Attributes.Name, e.Attributes.Code)
	}
}
