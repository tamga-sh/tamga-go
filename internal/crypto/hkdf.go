// Package crypto — hkdf.go holds DeriveMachineFileKey, the AES key
// derivation for an encrypted .machine (machine checkout) file.
//
// This IS a proper KDF (HKDF-SHA256, RFC 5869), unlike naivekey.go's
// license-file key derivation — do not conflate the two or "simplify" one
// to match the other; they intentionally back different file formats.
// golang.org/x/crypto/hkdf is this module's sole external dependency (see
// CLAUDE.md's "Critical Dependency Notes") — needed here because HKDF has
// no stdlib implementation, unlike every other primitive this SDK uses.
//
// Unlike license checkout's naive derivation (key-string only), decrypting
// a machine file requires BOTH the license key AND the target machine's
// fingerprint.
package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// machineFileKeySalt is the fixed HKDF salt for machine-file key
// derivation (docs/sdk.md §6).
const machineFileKeySalt = "tamga:machine-file-key-v1"

// DeriveMachineFileKey derives the 32-byte AES-256-GCM key for an
// encrypted .machine file via HKDF-SHA256: salt="tamga:machine-file-key-v1",
// ikm=licenseKey, info=fingerprint. HKDF (rather than a raw
// SHA256(licenseKey || fingerprint) concatenation) avoids a
// prefix-collision between the two inputs — see hkdf_test.go's dedicated
// test for that property.
func DeriveMachineFileKey(licenseKey, fingerprint string) ([32]byte, error) {
	var key [32]byte
	reader := hkdf.New(sha256.New, []byte(licenseKey), []byte(machineFileKeySalt), []byte(fingerprint))
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return key, fmt.Errorf("tamga: hkdf-sha256: %w", err)
	}
	return key, nil
}
