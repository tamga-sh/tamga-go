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

	"github.com/tamga-sh/tamga-go"
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

	// ActivateMachine composes CreateMachine + ValidateByID. A policy
	// limit can stop it at either step and both are reported the same
	// way — a nil *Machine plus an error matching ErrMachineOverLimit,
	// with meta carrying the exact code:
	//
	//   - Under a strict policy the server refuses creation outright
	//     (422 MACHINE_LIMIT_EXCEEDED and friends); no row exists, so
	//     nothing is rolled back.
	//   - Under an overage strategy creation succeeds and the limit only
	//     surfaces at validate; ActivateMachine deletes the row it just
	//     created before returning.
	//
	// Either way, check err before touching the returned machine.
	machine, meta, err := client.ActivateMachine(ctx, tamga.CreateMachineOptions{
		Fingerprint: *fingerprint,
		LicenseID:   *licenseID,
	}, nil)
	if err != nil {
		if errors.Is(err, tamga.ErrMachineOverLimit) {
			log.Fatalf("activation rejected: over policy limit (code=%s); no machine is registered", meta.Code)
		}
		log.Fatalf("ActivateMachine: %v", err)
	}
	fmt.Printf("activated machine %s: valid=%v code=%s\n", machine.ID, meta.Valid, meta.Code)

	if *heartbeat {
		hbCtx, cancel := context.WithTimeout(ctx, 3*tamga.DefaultHeartbeatInterval)
		defer cancel()

		// No heartbeat_status is a stop condition, so this callback logs
		// whatever comes back and lets the loop keep ticking. The one
		// signal that ends it is a 404 from the ping — the row is genuinely
		// gone. That, and only that, is where re-activation belongs.
		//
		// There is deliberately no `case ... == tamga.HeartbeatDead` here.
		// A ping writes last_heartbeat_at = NOW() and then derives the
		// status from that same timestamp, so its response is always ALIVE
		// or RESURRECTED; such a branch would be dead code. DEAD is a real
		// server state, but it is only visible from a machine read this SDK
		// does not expose yet.
		onTick := func(m *tamga.Machine, tickErr error) {
			switch {
			case errors.Is(tickErr, tamga.ErrNotFound):
				fmt.Println("heartbeat: machine row is gone (404) — re-activate here")
				cancel()
			case tickErr != nil:
				fmt.Printf("heartbeat: ping failed (will retry on the next tick): %v\n", tickErr)
			default:
				fmt.Printf("heartbeat: status %s\n", m.Attributes.HeartbeatStatus)
			}
		}

		// Interval 0 takes DefaultHeartbeatInterval, which is window/3 of
		// the server's 600s *fallback* window. That is only correct for a
		// policy that leaves heartbeat_duration null; a policy with a
		// shorter window needs an explicit interval passed here.
		scheduler := tamga.NewHeartbeatScheduler(client, machine.ID, 0 /* use the recommended default interval */, tamga.WithHeartbeatOnTick(onTick))
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
