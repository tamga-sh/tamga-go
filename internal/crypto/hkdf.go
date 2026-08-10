// hkdf.go will hold:
//
//	DeriveMachineFileKey(licenseKey, fingerprint string) ([32]byte, error)
//
// HKDF-SHA256 via golang.org/x/crypto/hkdf: salt="tamga:machine-file-key-v1",
// ikm=<license key>, info=<machine fingerprint> -> 32-byte AES key
// (docs/sdk.md §6). This IS a proper KDF, unlike naivekey.go's license-file
// key derivation — do not conflate the two or "simplify" one to match the
// other; they intentionally back different file formats.
//
// The golang.org/x/crypto/hkdf import below exists only to pin this
// module's sole external dependency during scaffolding
// (docs/plans/tamga-go.plan.md Section A), ahead of Section F's real
// implementation.
//
// Not implemented yet — scaffold placeholder. Tests will cover RFC
// 5869-style vectors plus a fixed salt/info reproducibility test
// (internal/crypto/hkdf_test.go).
package crypto

import _ "golang.org/x/crypto/hkdf"
