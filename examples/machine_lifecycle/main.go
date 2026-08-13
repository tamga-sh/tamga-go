// Command machine_lifecycle demonstrates the full machine lifecycle:
// create + ActivateMachine (with rollback-delete on an over-limit
// ValidationCode), a background HeartbeatScheduler, and generating +
// verifying a lightweight offline proof.
//
// Run:
//
//	go run ./examples/machine_lifecycle \
//	  -account acct-123 -key lic-abc123 -license lic-id \
//	  -fingerprint this-machine-fingerprint \
//	  -rsa-pubkey <base64 SPKI DER RSA public key>
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/tamga-sh/tamga-go/v2"
)

func main() {
	var (
		accountID    = flag.String("account", "", "Tamga account ID (required)")
		key          = flag.String("key", "", "license key (required)")
		licenseID    = flag.String("license", "", "license ID to activate a machine against (required)")
		fingerprint  = flag.String("fingerprint", "", "this machine's fingerprint (required)")
		rsaPubKeyB64 = flag.String("rsa-pubkey", "", "base64 SPKI DER RSA public key, for verifying the offline proof (required)")
		heartbeat    = flag.Bool("heartbeat", false, "run a background HeartbeatScheduler for a few ticks before exiting")
	)
	flag.Parse()
	if *accountID == "" || *key == "" || *licenseID == "" || *fingerprint == "" || *rsaPubKeyB64 == "" {
		log.Fatal("usage: machine_lifecycle -account <account-id> -key <license-key> -license <license-id> -fingerprint <fp> -rsa-pubkey <base64-pubkey> [-heartbeat]")
	}
	rsaDER, err := base64.StdEncoding.DecodeString(*rsaPubKeyB64)
	if err != nil {
		log.Fatalf("decode -rsa-pubkey: %v", err)
	}
	rsaPubAny, err := x509.ParsePKIXPublicKey(rsaDER)
	if err != nil {
		log.Fatalf("parse -rsa-pubkey: %v", err)
	}
	rsaPub, ok := rsaPubAny.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("-rsa-pubkey did not contain an RSA public key, got %T", rsaPubAny)
	}

	client, err := tamga.New(*accountID, tamga.WithLicenseKey(*key))
	if err != nil {
		log.Fatalf("tamga.New: %v", err)
	}
	ctx := context.Background()

	// ActivateMachine composes CreateMachine + ValidateByID, deleting the
	// just-created machine again if validation comes back over-limit
	// (TOO_MANY_MACHINES/TOO_MANY_CORES/etc.) — see machine.go's doc
	// comment for why creation alone never enforces limits. On that
	// rollback path it returns a nil *Machine and an error matching
	// ErrMachineOverLimit — the machine has already been deleted
	// server-side by the time it returns, so check err before touching
	// the returned machine.
	machine, meta, err := client.ActivateMachine(ctx, tamga.CreateMachineOptions{
		Fingerprint: *fingerprint,
		LicenseID:   *licenseID,
	}, nil)
	if err != nil {
		if errors.Is(err, tamga.ErrMachineOverLimit) {
			log.Fatalf("activation rejected (code=%s) — the over-limit machine row has already been rolled back", meta.Code)
		}
		log.Fatalf("ActivateMachine: %v", err)
	}
	fmt.Printf("activated machine %s: valid=%v code=%s\n", machine.ID, meta.Valid, meta.Code)

	if *heartbeat {
		hbCtx, cancel := context.WithTimeout(ctx, 3*tamga.DefaultHeartbeatInterval)
		defer cancel()
		scheduler := tamga.NewHeartbeatScheduler(client, machine.ID, 0 /* use the recommended default interval */)
		fmt.Println("running heartbeat scheduler for a few ticks (this will take a while at the real ~200s default interval)...")
		if runErr := scheduler.Run(hbCtx); runErr != nil {
			fmt.Printf("heartbeat scheduler stopped: %v\n", runErr)
		}
	}

	// Offline proof: a lighter-weight alternative to full checkout for
	// periodic "prove this machine is still valid" pings. The caller must
	// retain the exact dataset value passed here — a proof string carries
	// no recoverable payload of its own, only a signature, so
	// VerifyOfflineProof needs the same (accountID, machineID,
	// fingerprint, dataset) tuple back to reconstruct what was signed.
	dataset := map[string]any{"checked_at": time.Now().UTC().Format(time.RFC3339)}
	_, proof, err := client.GenerateOfflineProof(ctx, machine.ID, dataset)
	if err != nil {
		log.Fatalf("GenerateOfflineProof: %v", err)
	}
	fmt.Printf("generated offline proof: %s\n", proof)

	// Verification works fully offline from this point on — no network
	// access is used below.
	if err := tamga.VerifyOfflineProof(rsaPub, *accountID, machine.ID, *fingerprint, dataset, proof); err != nil {
		log.Fatalf("VerifyOfflineProof: %v", err)
	}
	fmt.Println("offline proof verified successfully")
}
