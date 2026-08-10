package tamga

// client_test.go will hold table-driven tests for client.go, per
// docs/plans/tamga-go.plan.md Section B:
//
//   - one case per auth transport (Bearer / Basic x3 sub-forms / License /
//     Cookie / query param), asserting exact header/query wire format
//   - Tamga-Version default-vs-override
//   - Tamga-OTP header presence/absence
//   - response header parsing (Tamga-Edition/Tamga-Mode/X-Request-Id)
//   - quick-validate flat-JSON special-case parsing (no "data" envelope)
//   - account_id path-segment always present, including when account_id
//     looks like a code rather than a UUID
//
// No tests are implemented yet — this file exists so the package's test
// layout is scaffolded ahead of Section B's real implementation.
