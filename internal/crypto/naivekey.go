// naivekey.go will hold:
//
//	DeriveLicenseFileKey(licenseKey string) [32]byte
//
// the license key's raw UTF-8 bytes, zero-padded or truncated to exactly
// 32 bytes. This is NOT a hash or a KDF — it is an intentionally weak,
// non-standard transform mandated by server wire compatibility
// (docs/sdk.md §4). The implementation must byte-exactly replicate the
// server's transform, not approximate it with something "safer" — doing
// so would silently break decryption of every real server-issued
// encrypted .lic file. Do not "fix" this to use hkdf.go's real KDF; the
// two are deliberately different and back different file formats
// (license checkout vs. machine checkout, docs/plans/tamga-go.plan.md
// Section F's doc comment on hkdf.go says the same in reverse).
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section E; tests will cover the zero-pad/
// truncate boundary at key lengths 0, 1, 31, 32, 33, and 100 bytes
// (internal/crypto/naivekey_test.go).
package crypto
