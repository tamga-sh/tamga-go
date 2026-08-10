package tamga

// checkout_machine_test.go will hold, per docs/plans/tamga-go.plan.md
// Section F:
//
//   - parse a well-formed .machine PEM fixture
//   - Verify() with ED25519_SIGN, RSA_2048_PKCS1_SIGN,
//     RSA_2048_PKCS1_PSS_SIGN, and ECDSA_P256_SIGN
//   - Verify() rejects RSA_2048_JWT_RS256 with ErrSchemeNotSupported
//     before touching any crypto primitive
//   - TTL boundary tests (0, 1, 31536000, 31536001)
//   - HKDF decrypt requires the correct fingerprint; wrong fingerprint
//     fails decryption via auth-tag mismatch, not a silent garbage decrypt
//
// No tests are implemented yet. Fixtures will live in
// testdata/machine_file_ed25519.machine, machine_file_rsa_pkcs1.machine,
// machine_file_rsa_pss.machine, and machine_file_ecdsa.machine.
//
// This section carries a MANDATORY security-reviewer gate before merge —
// see docs/plans/tamga-go.plan.md §4.
