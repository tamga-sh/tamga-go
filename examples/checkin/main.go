// Command checkin demonstrates the check-in flow, gated on the license's
// policy require_check_in field rather than blindly retrying on
// CHECK_IN_NOT_REQUIRED (docs/sdk.md §3).
//
// Run:
//
//	go run ./examples/checkin -account acct-123 -key lic-abc123 -license lic-id
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/tamga-sh/tamga-go/v2"
)

func main() {
	var (
		accountID = flag.String("account", "", "Tamga account ID (required)")
		key       = flag.String("key", "", "license key, used as the auth credential (required)")
		licenseID = flag.String("license", "", "license ID to check in (required)")
	)
	flag.Parse()
	if *accountID == "" || *key == "" || *licenseID == "" {
		log.Fatal("usage: checkin -account <account-id> -key <license-key> -license <license-id>")
	}

	client, err := tamga.New(*accountID, tamga.WithLicenseKey(*key))
	if err != nil {
		log.Fatalf("tamga.New: %v", err)
	}
	ctx := context.Background()

	// A production integration should check the license's policy's
	// require_check_in field before ever scheduling a periodic check-in;
	// this example just demonstrates handling the resulting error.
	license, err := client.CheckIn(ctx, *licenseID)
	switch {
	case err == nil:
		fmt.Printf("checked in: last_check_in_at=%v\n", derefStr(license.Attributes.LastCheckInAt))
	case errors.Is(err, tamga.ErrCheckInNotRequired):
		// A caller error, not a transient failure — this license's
		// policy doesn't require check-in. Don't retry; stop scheduling
		// check-ins for this license instead.
		fmt.Println("check-in not required for this license — not an error condition to retry")
	default:
		log.Fatalf("CheckIn: %v", err)
	}
}

func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
