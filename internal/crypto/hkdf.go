// Package crypto — hkdf.go holds the HKDF-SHA256 key derivations for both
// offline file formats.
//
// Machine files always used a proper KDF. License files did not: before file
// format v2 the AES key was the license key's raw UTF-8 bytes zero-padded to
// 32, which meant an attacker holding a stolen .lic was not attacking a
// 256-bit key space but the license key's own entropy — a dictionary attack
// against the AEAD tag on an XXXX-XXXX-XXXX-XXXX-shaped string. The
// naivekey.go that implemented it is gone rather than deprecated: leaving it
// exported would let a caller silently keep using the weaker derivation.
//
// The two derivations differ in salt and info, and must not be conflated.
// Decrypting a machine file requires BOTH the license key AND the target
// machine's fingerprint, so a machine file cannot be opened anywhere but on
// the machine it was issued for; a license file is not bound to a machine.
//
// golang.org/x/crypto/hkdf is this module's sole external dependency (see
// CLAUDE.md's "Critical Dependency Notes") — needed here because HKDF has
// no stdlib implementation, unlike every other primitive this SDK uses.
package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// machineFileKeySalt is the fixed HKDF salt for machine-file key
// derivation (Tamga API protocol specification §6).
const machineFileKeySalt = "tamga:machine-file-key-v1"

// licenseFileKeySalt and licenseFileKeyInfo are the fixed HKDF parameters for
// license-file key derivation.
const (
	licenseFileKeySalt = "tamga:license-file-key-v1"
	licenseFileKeyInfo = "license-file"
)

// DeriveLicenseFileKey derives the 32-byte AES-256-GCM key for an encrypted
// .lic file via HKDF-SHA256: salt="tamga:license-file-key-v1",
// ikm=licenseKey, info="license-file".
//
// No fingerprint is involved — a license file is not bound to a machine.
func DeriveLicenseFileKey(licenseKey string) ([32]byte, error) {
	var key [32]byte
	reader := hkdf.New(sha256.New, []byte(licenseKey), []byte(licenseFileKeySalt), []byte(licenseFileKeyInfo))
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return key, fmt.Errorf("tamga: hkdf-sha256: %w", err)
	}
	return key, nil
}

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
