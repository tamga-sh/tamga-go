// Package tamga is the official Go SDK for Tamga. Integrate license
// activation, offline verification, and machine management into your Go
// applications.
//
// Import path: github.com/tamga-sh/tamga-go — the module path is the
// package's import path, with no pkg/ nesting, so the public API sits at
// the top level rather than behind an internal pkg/ directory.
//
// # Getting started
//
// Construct a Client with New, providing an account ID and an auth
// transport (WithLicenseKey is the primary transport for embedded/client
// SDKs and this package's own default):
//
//	client, err := tamga.New("your-account-id", tamga.WithLicenseKey("YOUR-LICENSE-KEY"))
//	if err != nil {
//		log.Fatal(err)
//	}
//	license, meta, err := client.ValidateByKey(context.Background(), "YOUR-LICENSE-KEY")
//
// # Authentication
//
// Authentication is enforced server-side on every endpoint this package
// calls. For the default license-key transport there is one precondition
// that is easy to miss and accounts for most "everything 401s" reports:
// the license's policy must set authentication_strategy to LICENSE or
// MIXED. That column defaults to TOKEN, and under TOKEN (or NONE) a raw
// license key is rejected with 401 LICENSE_NOT_ALLOWED — match it with
// errors.Is against ErrLicenseNotAllowed. It is a configuration
// precondition, not a transient failure; retrying will not fix it.
//
// Two other 401s come from the same gate: ErrLicenseSuspended (a
// suspended license never authenticates) and ErrLicenseExpired (an
// expired license, but only when its policy uses REVOKE_ACCESS — every
// other expiration strategy still authenticates and reports EXPIRED from
// a validate call instead).
//
// A license key authenticates as a narrower role than a bearer token:
// Client.ResetHeartbeat and Client.GenerateOfflineProof are role-gated
// above it and return 403 unconditionally under WithLicenseKey.
//
// See the examples/ directory (not part of this package, run individually
// via `go run ./examples/<name>`) for full runnable programs covering
// validation, check-in, offline license/machine file verification, the
// machine lifecycle, and entitlement checks. The protocol reference this
// package implements against is published at https://tamga.sh.
//
// # Offline checkout file format v2
//
// LicenseFile.Verify accepts only format-v2 .lic files: Alg must be
// AlgBase64Ed25519 ("base64+ed25519+v2") or AlgAES256GCMEd25519
// ("aes-256-gcm+ed25519+v2"), and the signed payload must carry the meta
// claims modeled by LicenseFileClaims (iat, exp, jti, kid). The signed exp
// is enforced with a 60-second clock-skew tolerance.
//
// A pre-v2 file is rejected with ErrMissingClaims and there is no fallback
// path — this is a behavioral break for callers holding v1-issued .lic
// files, which must be re-issued via Client.CheckOutLicense. The key
// derivation changed with the format: the license-file AES key is now
// HKDF-SHA256, replacing (not deprecating) the earlier transform.
//
// Machine files (.machine) are format v2 on the same terms, and this
// package used to say the opposite. MachineFile.Alg is a three-part
// "<encoding>+<signing suffix>+v2" string — "base64+ed25519+v2",
// "aes-256-gcm+rsa-pss-sha256+v2" and so on, where the signing suffix
// follows the license's own LicenseScheme rather than always being Ed25519
// — and a file without the +v2 marker is refused. The payload carries the
// same LicenseFileClaims, surfaced on MachinePayload.Claims, and its exp is
// enforced with the same tolerance and the same *ExpiredError. Use
// MachineFile.Now to supply a trusted timestamp, as with LicenseFile.Now.
//
// Two shape differences from a .lic file are load-bearing. The signing
// scheme must be passed in by the caller and is never read out of Alg: the
// server emits the same "rsa-sha256" suffix for both
// SchemeRSA2048PKCS1Sign and SchemeRSA2048JWTRS256, so the suffix cannot
// identify the scheme (SchemeRSA2048JWTRS256 itself is refused up front).
// And an encrypted machine file's Enc is "<nonce_b64>.<ciphertext_b64>" —
// two separately base64-encoded halves — where an encrypted .lic file's Enc
// is a single base64 blob of nonce||ciphertext||tag. See
// MachineFile.Verify.
//
// # Rate limiting
//
// A 429 response is retried transparently: the server's Retry-After is
// honored (capped), and otherwise the client falls back to jittered
// exponential backoff. Auto-retry covers GET plus the validate,
// validate-key, check-in, check-out, ping, ping-heartbeat, and
// reset-heartbeat POST actions; resource creation is deliberately
// excluded, since repeating it can consume a second seat. Tune the budget
// with WithMaxRetries (default DefaultMaxRetries); passing 0 surfaces the
// *APIError immediately.
//
// # Machine heartbeats
//
// HeartbeatScheduler pings one machine on a timer
// (DefaultHeartbeatInterval, window/3) until its context is canceled.
//
// The server's window is the policy's heartbeat_duration when that field
// is set, and 600s only as a fallback when it is null.
// DefaultHeartbeatInterval is computed against that 600s fallback, so on
// a policy with a shorter heartbeat_duration it pings too slowly and the
// machine reads DEAD between ticks. Read the real window instead:
//
//	interval, err := client.HeartbeatIntervalForLicense(ctx, licenseID)
//	if err != nil {
//		interval = tamga.DefaultHeartbeatInterval
//	}
//	go tamga.NewHeartbeatScheduler(client, machineID, interval).Run(ctx)
//
// Do not try to derive it from a Machine's NextHeartbeatAt: that field is
// computed against the policy on some routes and against the 600s
// fallback on others, and a client holding a Machine cannot tell which it
// has. See MachineAttributes for the per-route table.
//
// The single most important thing to get right: the loop must not stop
// on ANY HeartbeatStatus, and the only terminal signal from a ping is a
// 404 NOT_FOUND (errors.Is(err, ErrNotFound)), meaning the row is gone.
// Hang re-activation off that and nothing else; observe it per tick with
// WithHeartbeatOnTick. HeartbeatScheduler.Run never inspects the status,
// and only context cancellation ends its loop.
//
// DEAD is not reachable from the heartbeat routes. Client.PingHeartbeat
// writes last_heartbeat_at = NOW() and then derives the status from that
// same timestamp, so its response is always ALIVE or RESURRECTED;
// Client.ResetHeartbeat and Client.CreateMachine both answer NOT_STARTED.
// A `case DEAD` branch written against a ping is dead code.
//
// It is reachable from five routes: Client.GetMachine,
// Client.ListMachines, Client.CheckOutMachine (on MachinePayload.Data,
// after MachineFile.Verify), Client.GenerateOfflineProof (on the *Machine
// it returns) and Client.UpdateMachine. The first four resolve the
// machine by reading a row rather than writing one and join the policy,
// so their HeartbeatStatus and NextHeartbeatAt reflect the real
// heartbeat_duration. Client.UpdateMachine is the counterexample that
// keeps the rule honest: a write, but one that touches none of the
// heartbeat columns, so it judges an untouched timestamp and can report
// DEAD — while its UPDATE … RETURNING omits the policies join, so it
// computes both fields against the 600s fallback. The rule is about which
// columns the statement touched, not about the HTTP verb.
//
// Wherever it appears, DEAD means only that the last ping is older than
// the window — never that the row was culled, deleted, or deactivated. The server derives the status from last_heartbeat_at alone
// and never consults the policy's require_heartbeat flag, and the culling
// job that would delete the row early-returns unless require_heartbeat is
// set — which it is not, by default. A machine can therefore report DEAD
// indefinitely while its row and its seat are still there.
//
// # Auto-update and health
//
// Client.CheckUpgrade wraps GET /releases/actions/upgrade. It returns
// (release, offered, error), and offered == false must NOT be reported as
// "you are up to date": the server answers 204 both when no newer release
// matches and when one exists that this license is not entitled to move
// to, deliberately, so that a refusal cannot leak a release's existence.
//
// Client.Health probes GET /v1/health. It is the one call in this package
// sent with no credential at all — the server resolves a request's bearer
// before it consults its public-route list, so a suspended or
// policy-refused license key would 401 the very call meant to rule the
// credential out. It is also the one path built without the
// /v1/accounts/{account_id} prefix, and its body is flat rather than
// JSON:API.
//
// # Request deadlines
//
// Every request is bounded by DefaultTimeout (45s), deliberately longer
// than the server's own 30s timeout so a slow call surfaces as the
// server's 504 — which carries an X-Request-Id — rather than racing it to
// a local deadline error. WithHTTPClient replaces that client entirely,
// so a supplied client with no Timeout restores unbounded requests.
//
// # File map
//
//   - client.go             Client struct, functional options, 429 retry/backoff
//   - transport.go          AuthTransport implementations (Bearer/Basic/License/Cookie/query)
//   - license.go            License resource, ValidateByKey/ByID/QuickValidate, CheckIn
//   - machine.go            Machine/Component/Process CRUD, heartbeats, schedulers
//   - machine_read.go       Machine get/list/update, fingerprint lookup, re-activation
//   - process_read.go       Machine process listing, process delete, scheduler disposal
//   - validation.go         ValidationCode string enum (24 values, 16 reachable today)
//   - entitlement.go        Entitlement resource, list/get, HasEntitlement(code) helper
//   - policy.go             LicenseScheme/OverageStrategy/heartbeat enums, Policy resource
//   - policy_read.go        Policy/license reads, policy-derived heartbeat window
//   - release.go            Release resource and the auto-update check
//   - health.go             Unauthenticated /v1/health probe
//   - checkout_license.go   .lic file parse/verify (Ed25519 signature + HKDF-derived AES key)
//   - checkout_machine.go   .machine file parse/verify (multi-scheme signature + HKDF key)
//   - proof.go              Offline proof generate/verify (RSA, byte-exact JSON serialization)
//   - errors.go             JSON:API error model, APIError with Is()/As() code matching
//
// internal/crypto/ holds the unexported cryptographic primitives backing
// checkout_license.go, checkout_machine.go, and proof.go. It is not
// importable outside this module — consumers call LicenseFile.Verify() and
// friends, never a crypto primitive directly. See internal/crypto/doc.go.
package tamga
