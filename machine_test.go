package tamga

// machine_test.go will hold, per docs/plans/tamga-go.plan.md Sections G
// and I:
//
//   - CreateMachine with the full optional-field set
//   - CreateMachine 409 FINGERPRINT_TAKEN mapping
//   - ActivateMachine happy path
//   - ActivateMachine rollback-delete on a TOO_MANY_MACHINES validation code
//   - PingHeartbeat/ResetHeartbeat request shape (no body)
//   - HeartbeatStatus enum JSON round-trip including unknown-value passthrough
//   - HeartbeatScheduler ticks at the expected interval and stops cleanly
//     on context cancel
//   - CreateComponent required-field validation + 409 FINGERPRINT_TAKEN
//   - ListComponents keyset-pagination cursor round-trip
//   - CreateProcess serializes PID as a JSON string even when constructed
//     from a numeric literal in Go
//   - CreateProcess 409 PID_TAKEN mapping
//   - PingProcess request shape
//   - ProcessHeartbeatScheduler default interval assertion (<= 10s)
//
// No tests are implemented yet.
