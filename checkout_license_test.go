package tamga

// checkout_license_test.go will hold, per docs/plans/tamga-go.plan.md
// Section E:
//
//   - parse a well-formed .lic PEM fixture end-to-end
//   - Verify() succeeds against a known-good Ed25519 test keypair + fixture
//   - Verify() FAILS when the implementation is deliberately rewired to
//     check the signature against enc's decoded bytes instead of the
//     base64 string — the regression guard for this section's central
//     gotcha
//   - encrypted variant end-to-end decrypt with naive key derivation
//     across license-key lengths <32, ==32, >32 bytes
//   - a godoc Example for LicenseFile.Verify (Section L)
//
// No tests are implemented yet. Fixtures will live in
// testdata/license_file_plain.lic, testdata/license_file_encrypted.lic,
// and testdata/ed25519_test_keypair.json (test-only keys, non-production).
//
// This section carries a MANDATORY security-reviewer gate before merge —
// see docs/plans/tamga-go.plan.md §4.
