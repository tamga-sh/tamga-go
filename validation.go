package tamga

import "time"

// ValidationCode is the license validation result code returned as
// meta.code by all three validation endpoints (docs/sdk.md §2). It is a
// plain string type rather than a closed Go enum on purpose: decoding an
// unknown value into a string never fails, so this SDK never hard-errors
// against a code the server adds in the future — callers that only
// recognize known constants should fall back to a default case on switch.
//
// Only 14 of the 24 values below are reachable against the current server
// implementation; the rest are declared for schema completeness and
// forward-compatibility. Each constant below is marked reachable (✅) or
// not (⛔) as of the server behavior documented in docs/sdk.md §2 and
// docs/plans/tamga-go.plan.md Section K — do not build product logic
// around a ⛔ value returning from a live call today.
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
	// ValidationCodeEntitlementsMissing declared in the enum, never emitted. ⛔ unreachable.
	ValidationCodeEntitlementsMissing ValidationCode = "ENTITLEMENTS_MISSING"
	// ValidationCodeTooManyUsers declared in the enum, never emitted. ⛔ unreachable.
	ValidationCodeTooManyUsers ValidationCode = "TOO_MANY_USERS"
	// ValidationCodeHeartbeatDead declared in the enum, never emitted. ⛔ unreachable.
	ValidationCodeHeartbeatDead ValidationCode = "HEARTBEAT_DEAD"
	// ValidationCodeHeartbeatNotStarted declared in the enum, never emitted. ⛔ unreachable.
	ValidationCodeHeartbeatNotStarted ValidationCode = "HEARTBEAT_NOT_STARTED"
	// ValidationCodeFingerprintScopeMismatch the scope.fingerprint field is
	// parsed but not checked server-side. ⛔ unreachable.
	ValidationCodeFingerprintScopeMismatch ValidationCode = "FINGERPRINT_SCOPE_MISMATCH"
	// ValidationCodeComponentsScopeMismatch declared in the enum, never emitted. ⛔ unreachable.
	ValidationCodeComponentsScopeMismatch ValidationCode = "COMPONENTS_SCOPE_MISMATCH"
	// ValidationCodeChecksumScopeMismatch the scope.checksum field is
	// parsed but not checked server-side. ⛔ unreachable.
	ValidationCodeChecksumScopeMismatch ValidationCode = "CHECKSUM_SCOPE_MISMATCH"
	// ValidationCodeVersionScopeMismatch the scope.version field is parsed
	// but not checked server-side. ⛔ unreachable.
	ValidationCodeVersionScopeMismatch ValidationCode = "VERSION_SCOPE_MISMATCH"
)

// ValidationMeta is the `{ts, valid, detail, code}` object returned
// alongside a license resource from ValidateByKey/ValidateByID (as the
// JSON:API response's meta block), and as the entire flat body of
// QuickValidate (docs/sdk.md §2). Code is stable and should drive branching
// logic; Detail is human text and may change wording between server
// versions.
type ValidationMeta struct {
	TS     time.Time      `json:"ts"`
	Detail string         `json:"detail"`
	Code   ValidationCode `json:"code"`
	Valid  bool           `json:"valid"`
}
