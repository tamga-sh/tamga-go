// checkout_license.go will hold CheckOutLicense (GET/POST
// .../licenses/{id}/actions/check-out), the LicenseFile struct
// ({Enc, Sig, Alg string} plus raw PEM text), ParseLicenseFile (strips the
// -----BEGIN/END LICENSE FILE----- markers), and (*LicenseFile).Verify —
// the full verify -> decrypt -> parse pipeline for an offline .lic file.
//
// The central gotcha this file must get exactly right (docs/sdk.md §4):
// the Ed25519 signature covers enc's ASCII/UTF-8 bytes of the base64
// STRING itself, not enc's decoded bytes. Get this backwards and every
// signature check silently fails against real server output while still
// passing against a self-generated fixture that repeats the same mistake.
//
// Encryption (alg == "aes-256-gcm+ed25519") uses a deliberately naive key
// derivation — the license key's raw UTF-8 bytes, zero-padded or truncated
// to 32 bytes, NOT a KDF (internal/crypto/naivekey.go) — because that is
// what the server actually does; "fixing" it to a real KDF would break
// interop with real server-issued files.
//
// alg is Ed25519-only for the checkout signature, independent of the
// license's own key scheme (unlike machine checkout in checkout_machine.go,
// which is scheme-driven).
//
// Not implemented yet — scaffold placeholder, and this file's real
// implementation carries a MANDATORY security-reviewer gate before merge.
// See docs/plans/tamga-go.plan.md Section E.
package tamga
