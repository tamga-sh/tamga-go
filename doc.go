// Package tamga is the official Go SDK for Tamga — license activation,
// offline (air-gapped) verification, and machine fleet management for
// license-embedded Go applications.
//
// Import path: github.com/tamga-sh/tamga-go — the module path is the
// package's import path, with no pkg/ nesting. This mirrors keygen-go
// rather than layouts that hide the public API behind an internal pkg/
// directory (see docs/plans/tamga-go.plan.md §2 Architecture).
//
// # Getting started
//
// Construct a Client with New, providing an account ID and an auth
// transport (WithLicenseKey is the primary transport for embedded/client
// SDKs and this package's own default):
//
//	client, err := tamga.New("your-account-id", tamga.WithLicenseKey("YOUR-LICENSE-KEY"))
//	if err != nil {
//		log.Fatal(err)
//	}
//	license, meta, err := client.ValidateByKey(context.Background(), "YOUR-LICENSE-KEY")
//
// See the examples/ directory (not part of this package, run individually
// via `go run ./examples/<name>`) for full runnable programs covering
// validation, check-in, offline license/machine file verification, the
// machine lifecycle, and entitlement checks. See
// docs/plans/tamga-go.plan.md for the full implementation task breakdown
// this package was built against, and
// https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md for the
// protocol reference.
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
