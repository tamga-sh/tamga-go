// Package crypto — naivekey.go holds DeriveLicenseFileKey, the AES key
// derivation for an encrypted .lic (license checkout) file.
//
// ⚠️ This is NOT a hash or a KDF — it is an intentionally weak,
// non-standard transform mandated by server wire compatibility
// (docs/sdk.md §4, ground-truth-verified against
// tamga-api/src/features/licenses/check_out_license.rs's own
// `key_bytes[..len].copy_from_slice(&kb[..len])` zero-pad/truncate
// derivation). Do not "fix" this to use a real KDF — that would silently
// break decryption of every real server-issued encrypted .lic file.
// Contrast with hkdf.go, which machine file (.machine) encryption uses
// instead and which IS a proper KDF; the two are deliberately different
// and back different file formats — do not conflate or "unify" them.
package crypto

// DeriveLicenseFileKey derives the AES-256-GCM key for an encrypted .lic
// file: licenseKey's raw UTF-8 bytes, zero-padded (if shorter than 32
// bytes) or truncated (if longer) to exactly 32 bytes.
func DeriveLicenseFileKey(licenseKey string) [32]byte {
	var key [32]byte
	copy(key[:], licenseKey) // copy stops at len(key) (32) automatically — this is the zero-pad/truncate transform
	return key
}
