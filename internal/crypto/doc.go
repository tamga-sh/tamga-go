// Package crypto holds the unexported cryptographic primitives backing
// license/machine checkout verification and offline proof verification.
//
// This package is internal by Go's own import-restriction rules: nothing
// outside github.com/tamga-sh/tamga-go can import it. That is a deliberate
// API design choice, not an accident of file placement — a consumer of
// this SDK should call (*LicenseFile).Verify(), never
// internal/crypto/ed25519.Verify() directly. Enforcing that boundary at
// compile time is more reliable than enforcing it through documentation.
//
// # File map
//
//   - ed25519.go   stdlib crypto/ed25519 wrapper — license + machine checkout signing
//   - rsa.go       stdlib crypto/rsa wrapper — PKCS1v15 + PSS verify
//   - ecdsa.go     stdlib crypto/ecdsa wrapper — P-256 verify
//   - aesgcm.go    stdlib crypto/cipher + crypto/aes wrapper — AES-256-GCM open/seal
//   - hkdf.go      golang.org/x/crypto/hkdf wrapper — the module's one external dependency
//   - naivekey.go  zero-pad/truncate-to-32-bytes transform — NOT a KDF, license checkout only
//
// stdlib covers every scheme this SDK verifies against except HKDF (needed
// for machine-file key derivation, docs/sdk.md §6) — golang.org/x/crypto/hkdf
// has no stdlib equivalent, which is why it is this module's sole external
// dependency (see docs/plans/tamga-go.plan.md §2).
//
// No file in this package is implemented yet — see
// docs/plans/tamga-go.plan.md Sections E, F, and H.
package crypto
