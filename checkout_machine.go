// checkout_machine.go will hold CheckOutMachine (GET/POST
// .../machines/{id}/actions/check-out, same encrypt/ttl shape as
// checkout_license.go), client-side TTL validation mirroring the server
// (> 0 and <= 31536000 seconds, short-circuiting with a typed
// ErrTTLInvalid before any request is sent), the MachineFile struct,
// ParseMachineFile (-----BEGIN/END MACHINE FILE----- markers), and
// (*MachineFile).Verify(scheme, pubKey) — dispatching to the
// algorithm-specific verifier for the license's LicenseScheme.
//
// Differences from license checkout (docs/sdk.md §6): the signing scheme
// is scheme-driven (ED25519_SIGN / RSA_2048_PKCS1_SIGN /
// RSA_2048_PKCS1_PSS_SIGN / ECDSA_P256_SIGN), with RSA_2048_JWT_RS256
// explicitly rejected (typed ErrSchemeNotSupported, checked before any
// crypto primitive is invoked — mirroring the server's own
// 422 SCHEME_NOT_SUPPORTED for this scheme specifically). Encryption key
// derivation is a proper HKDF-SHA256 (internal/crypto/hkdf.go), requiring
// both the license key and the target machine's fingerprint — unlike
// license checkout's naive derivation, which needs only the key.
//
// Reuses the same "sign over the base64 string, not decoded bytes"
// convention documented in checkout_license.go — do not re-derive that
// independently here.
//
// Not implemented yet — scaffold placeholder, and this file's real
// implementation carries a MANDATORY security-reviewer gate before merge.
// See docs/plans/tamga-go.plan.md Section F.
package tamga
