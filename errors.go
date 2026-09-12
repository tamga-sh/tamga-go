package tamga

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	internalcrypto "github.com/tamga-sh/tamga-go/internal/crypto"
)

// Error models a single JSON:API error object as returned by the Tamga API:
//
//	{"errors": [{id, status, code, title, detail, source: {pointer}}]}
//
// See the Tamga API protocol specification §11. code is stable and should
// drive matching logic; detail is human text and may change between server
// versions.
type Error struct {
	Source *ErrorSource `json:"source,omitempty"`
	// Meta is the error object's optional meta member, decoded leniently as
	// whatever JSON object the server sent; nil when absent. Today one code
	// populates it: a 409 FINGERPRINT_TAKEN carries {"machineId": "<uuid>"}
	// when — and only when — the machine already holding the fingerprint is
	// on the license the create was addressed to. Read it through
	// (*APIError).ConflictingMachineID rather than by key.
	//
	// Trailing field, keyed literals only: no unkeyed Error literal exists
	// in this module or its tests, and fieldalignment wants the pointer
	// fields ahead of the strings.
	Meta   map[string]any `json:"meta,omitempty"`
	ID     string         `json:"id,omitempty"`
	Status string         `json:"status,omitempty"`
	Code   string         `json:"code,omitempty"`
	Title  string         `json:"title,omitempty"`
	Detail string         `json:"detail,omitempty"`
}

// UnmarshalJSON decodes an error object, accepting status as either the
// JSON string the server renders ("422") or a JSON number (422). Status
// stays a string: callers compare it as one, and the HTTP status the error
// arrived with is on APIError.HTTPStatus anyway. Any other JSON type for
// status is an error, so a malformed envelope still degrades to UNKNOWN in
// mapError rather than being half-read.
func (e *Error) UnmarshalJSON(b []byte) error {
	// Slice last for fieldalignment; every other field carries a pointer.
	var wire struct {
		Source *ErrorSource    `json:"source"`
		Meta   map[string]any  `json:"meta"`
		ID     string          `json:"id"`
		Code   string          `json:"code"`
		Title  string          `json:"title"`
		Detail string          `json:"detail"`
		Status json.RawMessage `json:"status"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	status, err := decodeErrorStatus(wire.Status)
	if err != nil {
		return err
	}
	*e = Error{Source: wire.Source, Meta: wire.Meta, ID: wire.ID, Status: status, Code: wire.Code, Title: wire.Title, Detail: wire.Detail}
	return nil
}

// decodeErrorStatus renders a raw status member as the string this package
// has always carried: "" for absent or null, the string itself, or the
// number's decimal text.
func decodeErrorStatus(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", err
		}
		return s, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", fmt.Errorf("tamga: error object status must be a string or a number, got %s", raw)
	}
	return n.String(), nil
}

// ErrorSource carries the JSON:API error object's optional source.pointer,
// identifying which part of a request body a validation error applies to.
type ErrorSource struct {
	Pointer string `json:"pointer,omitempty"`
}

// ErrorResponse is the top-level JSON:API error envelope every non-2xx
// response from the API decodes into (except the quick-validate endpoint's
// flat-JSON shape, which is not a JSON:API error and is handled separately
// once client.go's decoder lands).
type ErrorResponse struct {
	Errors []Error `json:"errors"`
}

// APIError wraps a single Error plus the HTTP status it arrived with and
// implements the error interface. Every non-2xx response from this package
// is mapped to an *APIError; match against the sentinels declared below
// (ErrNotFound, ErrFingerprintTaken, ...) with errors.Is, which compares on
// the stable Code rather than the human-readable Detail.
type APIError struct {
	Err        Error
	Response   ResponseInfo
	HTTPStatus int
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil *APIError>"
	}
	return e.Err.Code + ": " + e.Err.Detail
}

// Is reports whether target is an *APIError with the same Code, so that
// errors.Is(err, someSentinel) works regardless of wrapping. Matching is
// deliberately on Code (stable, per the Tamga API protocol specification
// §11) and never on Detail (human text, may change between server
// versions).
func (e *APIError) Is(target error) bool {
	var t *APIError
	if !errors.As(target, &t) || t == nil {
		return false
	}
	return e.Err.Code == t.Err.Code
}

// As supports errors.As(err, &apiErr) extraction of the concrete *APIError
// from a wrapped error chain.
func (e *APIError) As(target any) bool {
	t, ok := target.(**APIError)
	if !ok {
		return false
	}
	*t = e
	return true
}

// MeterEntitlementID returns the id of the entitlement whose meter cap a
// 422 METER_LIMIT_EXCEEDED refused, and true, when the server supplied it
// in meta.entitlement_id — the same pattern ConflictingMachineID uses
// below for FINGERPRINT_TAKEN's meta.machineId.
//
// Raised by IncrementEntitlementUsage/DecrementEntitlementUsage
// (entitlement.go) when current_value + increment would exceed a kind:
// "meter" entitlement's max_value; lets a caller juggling several meters
// on one license tell which one hit its cap without re-parsing the
// request.
func (e *APIError) MeterEntitlementID() (string, bool) {
	if e == nil || e.Err.Code != ErrMeterLimitExceeded.Err.Code {
		return "", false
	}
	id, ok := e.Err.Meta["entitlement_id"].(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// ConflictingMachineID returns the id of the machine that already holds the
// fingerprint a 409 FINGERPRINT_TAKEN refused, and true, when the server
// supplied it in meta.machineId.
//
// The server sends it only when that machine is on the license the create
// was addressed to (API patch, machines/service.rs), so a returned id is
// always the caller's own seat, never another license's. A cross-license
// conflict under UNIQUE_PER_POLICY or UNIQUE_PER_ACCOUNT carries no meta and
// answers ("", false); so does any other code, and any pre-patch server.
// ActivateMachineIdempotent uses this as its fast path ahead of
// FindMachineByFingerprint.
func (e *APIError) ConflictingMachineID() (string, bool) {
	if e == nil || e.Err.Code != ErrFingerprintTaken.Err.Code {
		return "", false
	}
	id, ok := e.Err.Meta["machineId"].(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// Sentinel errors, fixed-status codes (Tamga API protocol specification
// §11). Match against these with errors.Is; a real *APIError always
// carries the server's own Detail/HTTPStatus, these sentinels only pin the
// stable Code.
//
// ⚠️ Treat every sentinel below as read-only. APIError's fields (Err,
// HTTPStatus, Response) are exported so this package can populate a fresh
// *APIError from a real server response (see mapError/
// newAPIErrorFromResponse) — but that same mutability means code with a
// reference to one of these package-level sentinels could, in principle,
// mutate it in place (e.g. ErrNotFound.Err.Code = "..."), corrupting
// errors.Is matching for every other caller in the process for the
// lifetime of the program. Never write to a sentinel's fields; construct
// your own *APIError (or use fmt.Errorf's %w) if you need a similar but
// distinct error value.
var (
	ErrNotFound            = &APIError{HTTPStatus: 404, Err: Error{Code: "NOT_FOUND"}}
	ErrUnauthorized        = &APIError{HTTPStatus: 401, Err: Error{Code: "UNAUTHORIZED"}}
	ErrForbidden           = &APIError{HTTPStatus: 403, Err: Error{Code: "FORBIDDEN"}}
	ErrInternal            = &APIError{HTTPStatus: 500, Err: Error{Code: "INTERNAL_SERVER_ERROR"}}
	ErrKeyTaken            = &APIError{HTTPStatus: 409, Err: Error{Code: "KEY_TAKEN"}}
	ErrFingerprintTaken    = &APIError{HTTPStatus: 409, Err: Error{Code: "FINGERPRINT_TAKEN"}}
	ErrPIDTaken            = &APIError{HTTPStatus: 409, Err: Error{Code: "PID_TAKEN"}}
	ErrCheckInNotRequired  = &APIError{HTTPStatus: 422, Err: Error{Code: "CHECK_IN_NOT_REQUIRED"}}
	ErrTTLInvalid          = &APIError{HTTPStatus: 422, Err: Error{Code: "TTL_INVALID"}}
	ErrLicenseNotEncrypted = &APIError{HTTPStatus: 422, Err: Error{Code: "LICENSE_NOT_ENCRYPTED"}}
	ErrLicenseKeyMissing   = &APIError{HTTPStatus: 422, Err: Error{Code: "LICENSE_KEY_MISSING"}}
	ErrSchemeNotSupported  = &APIError{HTTPStatus: 422, Err: Error{Code: "SCHEME_NOT_SUPPORTED"}}
	ErrDatasetInvalid      = &APIError{HTTPStatus: 422, Err: Error{Code: "DATASET_INVALID"}}
	// ErrSigningKeyMissing: the account holds no signing key for the
	// operation — a license or machine check-out, or an offline proof —
	// and the server refuses (422) rather than signing with nothing. Pre-
	// patch servers signed anyway and stamped UnpublishedSigningKeyID into
	// the file. Not retryable: an operator rotates a key in.
	ErrSigningKeyMissing = &APIError{HTTPStatus: 422, Err: Error{Code: "SIGNING_KEY_MISSING"}}
	// ErrSecretKeyMissing: token minting was refused because the account
	// has no secret key configured. Same remedy class as
	// ErrSigningKeyMissing — server-side configuration, never retryable.
	ErrSecretKeyMissing = &APIError{HTTPStatus: 422, Err: Error{Code: "SECRET_KEY_MISSING"}}
)

// Create-time policy-limit sentinels (HTTP 422). These are emitted by
// POST /machines and POST /processes *at creation time*, before any
// validate call — they are a different wire vocabulary from the
// TOO_MANY_*/TOO_MUCH_* ValidationCode values meta.code carries, even
// though they describe the same limits.
//
// This split is the single most confusing part of the machine-activation
// contract, so state it plainly:
//
//   - MACHINE_LIMIT_EXCEEDED / CORE_LIMIT_EXCEEDED /
//     MEMORY_LIMIT_EXCEEDED / DISK_LIMIT_EXCEEDED arrive as a 422
//     *APIError from CreateMachine.
//   - TOO_MANY_MACHINES / TOO_MANY_CORES / TOO_MUCH_MEMORY /
//     TOO_MUCH_DISK arrive as a ValidationCode in meta.code from
//     ValidateByID.
//
// Which of the two you see depends on the policy's overage strategy: the
// create-time check runs the same OverageStrategy comparison validation
// does, so a license under ALLOW_1_25X_OVERAGE (or ALWAYS_ALLOW_OVERAGE)
// can still be created past the nominal max and only report the overage
// later, at validate. ActivateMachine handles both paths and normalizes
// them onto ErrMachineOverLimit — see its doc comment.
//
// TOO_MANY_PROCESSES is the one code that is spelled identically in both
// vocabularies: CreateProcess returns it as a 422 *APIError, and
// validation also emits ValidationCodeTooManyProcesses.
var (
	ErrMachineLimitExceeded = &APIError{HTTPStatus: 422, Err: Error{Code: "MACHINE_LIMIT_EXCEEDED"}}
	ErrCoreLimitExceeded    = &APIError{HTTPStatus: 422, Err: Error{Code: "CORE_LIMIT_EXCEEDED"}}
	ErrMemoryLimitExceeded  = &APIError{HTTPStatus: 422, Err: Error{Code: "MEMORY_LIMIT_EXCEEDED"}}
	ErrDiskLimitExceeded    = &APIError{HTTPStatus: 422, Err: Error{Code: "DISK_LIMIT_EXCEEDED"}}
	ErrTooManyProcesses     = &APIError{HTTPStatus: 422, Err: Error{Code: "TOO_MANY_PROCESSES"}}
)

// ErrMeterLimitExceeded (HTTP 422, Err.Code "METER_LIMIT_EXCEEDED") is
// raised by IncrementEntitlementUsage/DecrementEntitlementUsage
// (entitlement.go) when a kind: "meter" entitlement's current_value plus
// the requested increment would exceed its max_value.
//
// It replaces the retired global usage counter's TOO_MANY_USES
// ValidationCode (see validation.go) for the new per-entitlement meters —
// but note it is a different wire vocabulary entirely, an *APIError from
// the increment/decrement action itself, never a ValidationCode from a
// validate call, the same MACHINE_LIMIT_EXCEEDED-vs-TOO_MANY_MACHINES
// split documented above for machines. Carries meta.entitlement_id —
// read it with (*APIError).MeterEntitlementID rather than by key.
var ErrMeterLimitExceeded = &APIError{HTTPStatus: 422, Err: Error{Code: "METER_LIMIT_EXCEEDED"}}

// License-key authentication sentinels (HTTP 401). These are refusals at
// the front door: the credential was recognized, the license row was
// found, and the server then declined to authenticate it. None of them is
// retryable — retrying with the same key produces the same 401 until
// something changes server-side.
//
//   - ErrLicenseSuspended: license.suspended is true. Suspended licenses
//     never authenticate, regardless of policy.
//   - ErrLicenseExpired: the license has expired AND its policy's
//     expiration_strategy is REVOKE_ACCESS (or an unrecognized value —
//     the server fails closed). Under RESTRICT_ACCESS, MAINTAIN_ACCESS,
//     or ALLOW_ACCESS an expired license still authenticates and instead
//     surfaces ValidationCodeExpired from a validate call.
//   - ErrLicenseNotAllowed: the policy's authentication_strategy is not
//     LICENSE or MIXED. This is a *configuration precondition*, not a
//     transient auth failure — see AuthenticationStrategy in policy.go.
//     The column defaults to TOKEN, so license-key auth is off by default
//     on a freshly created policy and every call fails this way until an
//     operator switches the policy to LICENSE or MIXED.
var (
	ErrLicenseSuspended  = &APIError{HTTPStatus: 401, Err: Error{Code: "LICENSE_SUSPENDED"}}
	ErrLicenseExpired    = &APIError{HTTPStatus: 401, Err: Error{Code: "LICENSE_EXPIRED"}}
	ErrLicenseNotAllowed = &APIError{HTTPStatus: 401, Err: Error{Code: "LICENSE_NOT_ALLOWED"}}
)

// NOTE: 429 TOO_MANY_REQUESTS is live and handled in the transport layer, not
// modeled as a sentinel here. (*Client).do (client.go) retries a throttled
// request transparently — capped Retry-After, otherwise jittered exponential
// backoff — for GET plus the safe POST actions listed in
// retryablePOSTSuffixes. Only once the retry budget (WithMaxRetries,
// default DefaultMaxRetries) is exhausted does the 429 surface to the caller,
// as an ordinary *APIError with HTTPStatus 429.

// Local (client-side, non-API) verification errors returned by
// (*LicenseFile).Verify and (*MachineFile).Verify — distinct from the
// server-error sentinels above (ErrLicenseKeyMissing/ErrLicenseNotEncrypted
// map to actual 422 API responses from a checkout *request*; these two are
// raised locally, offline, when Verify() itself is called without material
// its target file's algorithm requires to decrypt).
var (
	// ErrLicenseKeyRequired is returned when Verify is called with an
	// empty license key against a file whose alg requires decryption
	// (aes-256-gcm+...). Not the same condition as the server-side
	// ErrLicenseKeyMissing/ErrLicenseNotEncrypted sentinels, which come
	// from an API response to a checkout *request*, not a local Verify
	// call against an already-downloaded file.
	ErrLicenseKeyRequired = errors.New("tamga: license key is required to decrypt an encrypted checkout file")
	// ErrFingerprintRequired is returned when (*MachineFile).Verify is
	// called with an empty fingerprint against a file whose alg requires
	// decryption — machine files, unlike license files, need both the
	// license key AND the target machine's fingerprint to decrypt.
	ErrFingerprintRequired = errors.New("tamga: machine fingerprint is required to decrypt an encrypted machine file")
	// ErrUnsupportedAlgorithm is returned by every verifying entry point —
	// (*LicenseFile).Verify and VerifyWithKeySet, (*MachineFile).Verify and
	// VerifyWithKeySet — when the file's alg is not a recognized "+v2"
	// value. It is the FIRST check each of them makes, before any key is
	// consulted or any signature checked, so a pre-v2 or unknown file is
	// reported identically from every entry point and never as
	// ErrInvalidSignature (D17).
	ErrUnsupportedAlgorithm = errors.New("tamga: unsupported checkout file algorithm")
	// ErrDecryptionFailed is returned when the signature VERIFIED and the
	// AES-256-GCM open then failed. After a good signature that can only
	// mean the wrong license key — or, for a machine file, the wrong
	// fingerprint — never a forgery, which is why it is distinct from
	// ErrInvalidSignature (D16). It is the same value as
	// internal/crypto.ErrDecryptionFailed, re-exported so callers can match
	// it without importing an internal package.
	ErrDecryptionFailed = internalcrypto.ErrDecryptionFailed
	// ErrMachineOverLimit is returned by ActivateMachine when a policy
	// limit blocks activation. It covers both of the two places the
	// server can enforce that limit, so a caller only has to match one
	// error:
	//
	//  1. Create-time (422 MACHINE_LIMIT_EXCEEDED/CORE_LIMIT_EXCEEDED/
	//     MEMORY_LIMIT_EXCEEDED/DISK_LIMIT_EXCEEDED from POST /machines).
	//     No machine row was ever created, so there is nothing to roll
	//     back and ActivateMachine does NOT issue a delete.
	//  2. Validate-time (an over-limit ValidationCode —
	//     TOO_MANY_MACHINES/TOO_MANY_CORES/TOO_MUCH_MEMORY/
	//     TOO_MUCH_DISK/TOO_MANY_PROCESSES — from the ValidateByID call
	//     that follows creation). The machine WAS created, so
	//     ActivateMachine deletes it before returning.
	//
	// In both cases the returned *Machine is nil and the accompanying
	// *ValidationMeta carries the exact ValidationCode, so a caller can
	// tell which limit was exceeded without caring which of the two paths
	// produced it (create-time codes are normalized onto their
	// ValidationCode equivalent — see ActivateMachine). errors.Is(err,
	// ErrMachineOverLimit) matches regardless of wrapping; the underlying
	// create-time *APIError is also still in the chain, so
	// errors.Is(err, ErrMachineLimitExceeded) works on path 1.
	ErrMachineOverLimit = errors.New("tamga: machine activation rejected: over policy limit")
)

// newAPIErrorFromResponse maps a decoded ErrorResponse's first Error to an
// *APIError carrying the actual HTTP status and server-provided Detail.
// Because Is() matches only on Code, errors.Is(err, ErrFingerprintTaken)
// works against the returned value even though HTTPStatus/Detail differ
// from the sentinel's own zero-value Detail.
func newAPIErrorFromResponse(httpStatus int, resp ErrorResponse) *APIError {
	if len(resp.Errors) == 0 {
		return &APIError{
			HTTPStatus: httpStatus,
			Err: Error{
				Code:   "UNKNOWN",
				Title:  "Unknown Error",
				Detail: "server returned an empty errors array",
			},
		}
	}
	return &APIError{HTTPStatus: httpStatus, Err: resp.Errors[0]}
}
