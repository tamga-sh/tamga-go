// Package tamga is the official Go SDK for Tamga — license activation,
// offline (air-gapped) verification, and machine fleet management for
// license-embedded Go applications.
//
// Import path: github.com/tamga-sh/tamga-go — the module path is the
// package's import path, with no pkg/ nesting. This mirrors keygen-go
// rather than layouts that hide the public API behind an internal pkg/
// directory (see docs/plans/tamga-go.plan.md §2 Architecture).
//
// # Scaffold status
//
// This repository is currently infrastructure-only. No exported type below
// implements real HTTP or cryptographic logic yet — every file is a stub
// carrying only the doc comment describing its eventual contents, per
// docs/plans/tamga-go.plan.md Section A. Real implementation lands
// section-by-section (B through M) in a dedicated follow-up session; see
// that plan file's checkbox list for the authoritative work breakdown, and
// /Users/neco/Projects/tamga-api/docs/sdk.md for the protocol this SDK
// implements against.
//
// # File map
//
//   - client.go             Client struct, functional options, execute()
//   - transport.go          AuthTransport implementations (Bearer/Basic/License/Cookie/query)
//   - license.go            License resource, ValidateByKey/ByID/QuickValidate, CheckIn
//   - machine.go            Machine/Component/Process CRUD, heartbeats, schedulers
//   - validation.go         ValidationCode string enum (24 values, 14 reachable today)
//   - entitlement.go        Entitlement resource, list/get, HasEntitlement(code) helper
//   - policy.go             LicenseScheme/OverageStrategy/heartbeat enums, Policy resource
//   - checkout_license.go   .lic file parse/verify (Ed25519 signature + naive AES key)
//   - checkout_machine.go   .machine file parse/verify (multi-scheme signature + HKDF key)
//   - proof.go              Offline proof generate/verify (RSA, byte-exact JSON serialization)
//   - errors.go             JSON:API error model, APIError with Is()/As() code matching
//
// internal/crypto/ holds the unexported cryptographic primitives backing
// checkout_license.go, checkout_machine.go, and proof.go. It is not
// importable outside this module — consumers call LicenseFile.Verify() and
// friends, never a crypto primitive directly. See internal/crypto/doc.go.
package tamga
