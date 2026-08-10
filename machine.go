// machine.go will hold the Machine, Component, and Process resources and
// their CRUD/heartbeat operations:
//
//   - CreateMachine / ActivateMachine (create -> validate -> rollback-delete
//     on TOO_MANY_* — no machine/core/etc. limit is checked at creation
//     time, only later via license validation, per docs/sdk.md §5)
//   - PingHeartbeat / ResetHeartbeat, HeartbeatStatus enum
//     (NOT_STARTED -> ALIVE -> DEAD -> RESURRECTED) on a hardcoded 600s
//     window (NOT policy.heartbeat_duration, despite that field existing)
//   - HeartbeatScheduler — context-cancelable background pinger
//   - CreateComponent / ListComponents (keyset-paginated)
//   - CreateProcess / PingProcess — PID is a string on the wire, never
//     silently coerced to int; hardcoded 30s heartbeat window with NO
//     resurrection grace, unlike machines
//   - ProcessHeartbeatScheduler
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Sections G and I.
package tamga
