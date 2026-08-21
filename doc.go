// Package tamga is the official Go SDK for Tamga. Integrate license
// activation, offline verification, and machine management into your Go
// applications.
//
// Import path: github.com/tamga-sh/tamga-go — the module path is the
// package's import path, with no pkg/ nesting, so the public API sits at
// the top level rather than behind an internal pkg/ directory.
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
// # Authentication
//
// Authentication is enforced server-side on every endpoint this package
// calls. For the default license-key transport there is one precondition
// that is easy to miss and accounts for most "everything 401s" reports:
// the license's policy must set authentication_strategy to LICENSE or
// MIXED. That column defaults to TOKEN, and under TOKEN (or NONE) a raw
// license key is rejected with 401 LICENSE_NOT_ALLOWED — match it with
// errors.Is against ErrLicenseNotAllowed. It is a configuration
// precondition, not a transient failure; retrying will not fix it.
//
// Two other 401s come from the same gate: ErrLicenseSuspended (a
// suspended license never authenticates) and ErrLicenseExpired (an
// expired license, but only when its policy uses REVOKE_ACCESS — every
// other expiration strategy still authenticates and reports EXPIRED from
// a validate call instead).
//
// A license key authenticates as a narrower role than a bearer token:
// Client.ResetHeartbeat and Client.GenerateOfflineProof are role-gated
// above it and return 403 unconditionally under WithLicenseKey.
//
// See the examples/ directory (not part of this package, run individually
// via `go run ./examples/<name>`) for full runnable programs covering
// validation, check-in, offline license/machine file verification, the
// machine lifecycle, and entitlement checks. The protocol reference this
// package implements against is published at https://tamga.sh.
//
// # Offline license file format v2
//
// LicenseFile.Verify accepts only format-v2 .lic files: Alg must be
// AlgBase64Ed25519 ("base64+ed25519+v2") or AlgAES256GCMEd25519
// ("aes-256-gcm+ed25519+v2"), and the signed payload must carry the meta
// claims modeled by LicenseFileClaims (iat, exp, jti, kid). The signed exp
// is enforced with a 60-second clock-skew tolerance.
//
// A pre-v2 file is rejected with ErrMissingClaims and there is no fallback
// path — this is a behavioral break for callers holding v1-issued .lic
// files, which must be re-issued via Client.CheckOutLicense. The key
// derivation changed with the format: the license-file AES key is now
// HKDF-SHA256, replacing (not deprecating) the earlier transform.
//
// Machine files are a separate format and carry no signed claims; see
// MachineFile.Verify.
//
// # Rate limiting
//
// A 429 response is retried transparently: the server's Retry-After is
// honored (capped), and otherwise the client falls back to jittered
// exponential backoff. Auto-retry covers GET plus the validate,
// validate-key, check-in, check-out, ping, ping-heartbeat, and
// reset-heartbeat POST actions; resource creation is deliberately
// excluded, since repeating it can consume a second seat. Tune the budget
// with WithMaxRetries (default DefaultMaxRetries); passing 0 surfaces the
// *APIError immediately.
//
// # Request deadlines
//
// Every request is bounded by DefaultTimeout (45s), deliberately longer
// than the server's own 30s timeout so a slow call surfaces as the
// server's 504 — which carries an X-Request-Id — rather than racing it to
// a local deadline error. WithHTTPClient replaces that client entirely,
// so a supplied client with no Timeout restores unbounded requests.
//
// # File map
//
//   - client.go             Client struct, functional options, 429 retry/backoff
//   - transport.go          AuthTransport implementations (Bearer/Basic/License/Cookie/query)
//   - license.go            License resource, ValidateByKey/ByID/QuickValidate, CheckIn
//   - machine.go            Machine/Component/Process CRUD, heartbeats, schedulers
//   - validation.go         ValidationCode string enum (24 values, 16 reachable today)
//   - entitlement.go        Entitlement resource, list/get, HasEntitlement(code) helper
//   - policy.go             LicenseScheme/OverageStrategy/heartbeat enums, Policy resource
//   - checkout_license.go   .lic file parse/verify (Ed25519 signature + HKDF-derived AES key)
//   - checkout_machine.go   .machine file parse/verify (multi-scheme signature + HKDF key)
//   - proof.go              Offline proof generate/verify (RSA, byte-exact JSON serialization)
//   - errors.go             JSON:API error model, APIError with Is()/As() code matching
//
// internal/crypto/ holds the unexported cryptographic primitives backing
// checkout_license.go, checkout_machine.go, and proof.go. It is not
// importable outside this module — consumers call LicenseFile.Verify() and
// friends, never a crypto primitive directly. See internal/crypto/doc.go.
package tamga
