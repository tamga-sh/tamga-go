package tamga

import "time"

// ValidationCode is the license validation result code returned as
// meta.code by all three validation endpoints (Tamga API protocol
// specification §2). It is a plain string type rather than a closed Go
// enum on purpose: decoding an unknown value into a string never fails, so
// this SDK never hard-errors against a code the server adds in the future
// — callers that only recognize known constants should fall back to a
// default case on switch.
//
// Only 19 of the 24 values below are reachable against the patched server;
// the rest are declared for schema completeness and forward-compatibility.
// Each constant below is marked reachable (✅) or not (⛔) as of the server
// behavior documented in the Tamga API protocol specification §2 — do not
// build product logic around a ⛔ value returning from a live call today.
//
// The server evaluates validate-by-id in this order, first failing check
// wins: SUSPENDED, EXPIRED, OVERDUE, FINGERPRINT_SCOPE_MISMATCH,
// HEARTBEAT_NOT_STARTED, HEARTBEAT_DEAD, ENTITLEMENTS_MISSING,
// PRODUCT_SCOPE_MISMATCH, POLICY_SCOPE_MISMATCH, USER_SCOPE_MISMATCH,
// ENVIRONMENT_SCOPE_MISMATCH, TOO_MANY_MACHINES, TOO_MANY_CORES,
// TOO_MUCH_MEMORY, TOO_MUCH_DISK, TOO_MANY_PROCESSES, TOO_MANY_USERS,
// TOO_MANY_USES, then VALID.
//
// HEARTBEAT_NOT_STARTED, HEARTBEAT_DEAD and TOO_MANY_USERS moved from ⛔
// to ✅ with the API patch: the fingerprint scope emits the two heartbeat
// verdicts when policy.require_heartbeat is set, and all three validate
// endpoints emit TOO_MANY_USERS. None of the three joins isOverageCode —
// activation creates no users, and a heartbeat verdict is not a seat limit.
type ValidationCode string

const (
	// ValidationCodeValid all checks passed. ✅ reachable.
	ValidationCodeValid ValidationCode = "VALID"
	// ValidationCodeSuspended license.suspended == true. ✅ reachable.
	ValidationCodeSuspended ValidationCode = "SUSPENDED"
	// ValidationCodeExpired expiry < now. ✅ reachable.
	ValidationCodeExpired ValidationCode = "EXPIRED"
	// ValidationCodeOverdue check-in required and the window elapsed. ✅ reachable.
	ValidationCodeOverdue ValidationCode = "OVERDUE"
	// ValidationCodeProductScopeMismatch scope.product set and mismatched. ✅ reachable.
	ValidationCodeProductScopeMismatch ValidationCode = "PRODUCT_SCOPE_MISMATCH"
	// ValidationCodePolicyScopeMismatch scope.policy set and mismatched. ✅ reachable.
	ValidationCodePolicyScopeMismatch ValidationCode = "POLICY_SCOPE_MISMATCH"
	// ValidationCodeUserScopeMismatch scope.user set and mismatched. ✅ reachable.
	ValidationCodeUserScopeMismatch ValidationCode = "USER_SCOPE_MISMATCH"
	// ValidationCodeEnvironmentScopeMismatch scope.environment set and mismatched. ✅ reachable.
	ValidationCodeEnvironmentScopeMismatch ValidationCode = "ENVIRONMENT_SCOPE_MISMATCH"
	// ValidationCodeTooManyMachines machine count over policy.max_machines
	// (adjusted by the license's overage strategy). ✅ reachable.
	ValidationCodeTooManyMachines ValidationCode = "TOO_MANY_MACHINES"
	// ValidationCodeTooManyCores core count over policy.max_cores. ✅ reachable.
	ValidationCodeTooManyCores ValidationCode = "TOO_MANY_CORES"
	// ValidationCodeTooMuchMemory memory over policy.max_memory. ✅ reachable.
	ValidationCodeTooMuchMemory ValidationCode = "TOO_MUCH_MEMORY"
	// ValidationCodeTooMuchDisk disk over policy.max_disk. ✅ reachable.
	ValidationCodeTooMuchDisk ValidationCode = "TOO_MUCH_DISK"
	// ValidationCodeTooManyProcesses process count over policy.max_processes. ✅ reachable.
	ValidationCodeTooManyProcesses ValidationCode = "TOO_MANY_PROCESSES"
	// ValidationCodeTooManyUses uses >= max_uses, strict regardless of
	// overage strategy (overage strategies never apply to uses). ✅ reachable.
	ValidationCodeTooManyUses ValidationCode = "TOO_MANY_USES"

	// ValidationCodeNotFound modeled for schema completeness only — the
	// handler returns HTTP 404 directly instead of emitting this code in
	// practice. ⛔ unreachable.
	ValidationCodeNotFound ValidationCode = "NOT_FOUND"
	// ValidationCodeBanned declared in the enum, never emitted. ⛔ unreachable.
	ValidationCodeBanned ValidationCode = "BANNED"
	// ValidationCodeEntitlementsMissing scope.entitlements listed a code
	// the license does not hold, counting both directly-attached and
	// policy-inherited entitlements. Codes are compared
	// case-insensitively and de-duplicated; an empty list asserts
	// nothing. ✅ reachable.
	ValidationCodeEntitlementsMissing ValidationCode = "ENTITLEMENTS_MISSING"
	// ValidationCodeTooManyUsers users over policy.max_users, from all
	// three validate endpoints. Not an over-limit code: ActivateMachine
	// does not roll back on it. ✅ reachable.
	ValidationCodeTooManyUsers ValidationCode = "TOO_MANY_USERS"
	// ValidationCodeHeartbeatDead scope.fingerprint matched a machine whose
	// last ping is outside the window, under policy.require_heartbeat.
	// Emitted by the fingerprint scope only, never by a ping — PingHeartbeat
	// derives its own status from the timestamp it just wrote. ✅ reachable.
	ValidationCodeHeartbeatDead ValidationCode = "HEARTBEAT_DEAD"
	// ValidationCodeHeartbeatNotStarted scope.fingerprint matched a machine
	// that has never pinged, under policy.require_heartbeat. ✅ reachable.
	ValidationCodeHeartbeatNotStarted ValidationCode = "HEARTBEAT_NOT_STARTED"
	// ValidationCodeFingerprintScopeMismatch scope.fingerprint matched no
	// machine registered on the license. Any machine counts, whatever its
	// heartbeat status. ✅ reachable.
	ValidationCodeFingerprintScopeMismatch ValidationCode = "FINGERPRINT_SCOPE_MISMATCH"
	// ValidationCodeComponentsScopeMismatch declared in the enum, never emitted. ⛔ unreachable.
	ValidationCodeComponentsScopeMismatch ValidationCode = "COMPONENTS_SCOPE_MISMATCH"
	// ValidationCodeChecksumScopeMismatch unreachable by construction:
	// sending scope.checksum makes the server reject the request with
	// 422 SCOPE_NOT_SUPPORTED before validation runs, so this code can
	// never be the outcome. Scope.MarshalJSON drops the field. ⛔ unreachable.
	ValidationCodeChecksumScopeMismatch ValidationCode = "CHECKSUM_SCOPE_MISMATCH"
	// ValidationCodeVersionScopeMismatch unreachable by construction, for
	// the same reason as CHECKSUM_SCOPE_MISMATCH. ⛔ unreachable.
	ValidationCodeVersionScopeMismatch ValidationCode = "VERSION_SCOPE_MISMATCH"
)

// ValidationMeta is the `{ts, valid, detail, code}` object returned
// alongside a license resource from ValidateByKey/ValidateByID (as the
// JSON:API response's meta block), and as the entire flat body of
// QuickValidate (Tamga API protocol specification §2). Code is stable and
// should drive branching logic; Detail is human text and may change
// wording between server versions.
type ValidationMeta struct {
	TS     time.Time      `json:"ts"`
	Detail string         `json:"detail"`
	Code   ValidationCode `json:"code"`
	Valid  bool           `json:"valid"`
}
