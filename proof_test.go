package tamga

// proof_test.go will hold, per docs/plans/tamga-go.plan.md Section H:
//
//   - GenerateOfflineProof request/response round-trip
//   - byte-exact serialization regression test against a fixed golden
//     JSON fixture (catches field-order drift on refactor)
//   - VerifyOfflineProof succeeds against a known-good RSA test keypair +
//     fixture
//   - VerifyOfflineProof fails on a tampered dataset value
//   - VerifyOfflineProof fails when the payload is reconstructed with a
//     different (but same-content) field order — the regression guard for
//     this section's central gotcha
//
// No tests are implemented yet. Fixtures will live in
// testdata/offline_proof_golden.json and testdata/rsa_test_keypair.pem
// (test-only, non-production).
//
// This section carries a MANDATORY security-reviewer gate before merge —
// see docs/plans/tamga-go.plan.md §4.
