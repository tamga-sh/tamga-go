# github.com/tamga-sh/tamga-go

[![CI](https://github.com/tamga-sh/tamga-go/actions/workflows/ci.yml/badge.svg)](https://github.com/tamga-sh/tamga-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/tamga-sh/tamga-go.svg)](https://pkg.go.dev/github.com/tamga-sh/tamga-go)
[![coverage](https://codecov.io/gh/tamga-sh/tamga-go/branch/main/graph/badge.svg)](https://codecov.io/gh/tamga-sh/tamga-go)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Official Go SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Go applications.

## Install

```bash
go get github.com/tamga-sh/tamga-go
```

The import path is the module path — there is no `pkg/` nesting, and the package name is
`tamga`:

```go
import "github.com/tamga-sh/tamga-go"
```

Supported Go versions: 1.22 and 1.23 (the matrix `.github/workflows/ci.yml` gates on). The one
external dependency is `golang.org/x/crypto`, for HKDF.

## Quickstart

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/tamga-sh/tamga-go"
)

func main() {
	client, err := tamga.New("your-account-id", tamga.WithLicenseKey("YOUR-LICENSE-KEY"))
	if err != nil {
		log.Fatal(err)
	}

	license, meta, err := client.ValidateByKey(context.Background(), "YOUR-LICENSE-KEY")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("valid=%v code=%s license=%s\n", meta.Valid, meta.Code, license.ID)
}
```

Activating a machine is `ActivateMachine`, which creates the machine and then validates the
license, deleting the machine again if activation would exceed a limit:

```go
machine, meta, err := client.ActivateMachine(ctx, tamga.CreateMachineOptions{
	LicenseID:   license.ID,
	Fingerprint: "this-machine-fingerprint",
}, nil)
if errors.Is(err, tamga.ErrMachineOverLimit) {
	log.Fatalf("activation refused: %s", meta.Code)
}
if err != nil {
	log.Fatal(err)
}
fmt.Println(machine.ID, machine.Attributes.HeartbeatStatus)
```

Keep it alive with `NewHeartbeatScheduler(client, machine.ID, tamga.DefaultHeartbeatInterval)`
and `(*HeartbeatScheduler).Run(ctx)`, which pings until the context is canceled.

`examples/` holds runnable programs for validation, check-in, license/machine file verification,
the machine lifecycle, and entitlement checks — `go run ./examples/validate -h` to start.

## Auth transports

`tamga.New` requires exactly one auth transport, set via an `Option`. `WithLicenseKey` is the
primary transport for embedded/client SDKs and this package's own default path; use `WithAuth`
for any of the others (the server's try-order is Bearer → Basic → License → Cookie → query
param, but the SDK sends only the transport you configure).

| Transport | Wire form | Option |
|---|---|---|
| License key | `Authorization: License <key>` | `WithLicenseKey(key)` (shorthand) or `WithAuth(tamga.LicenseKeyAuth{Key: key})` |
| Bearer token | `Authorization: Bearer <token>` | `WithAuth(tamga.BearerAuth{Token: token})` |
| Basic — email/password | `Authorization: Basic base64(email:password)` | `WithAuth(tamga.NewBasicAuthEmailPassword(email, password))` |
| Basic — token | `Authorization: Basic base64(token:)` (empty password) | `WithAuth(tamga.NewBasicAuthToken(token))` |
| Basic — license key | `Authorization: Basic base64(license:<key>)` | `WithAuth(tamga.NewBasicAuthLicenseKey(key))` |
| Session cookie | `Cookie: Tamga-Session=<uuid>` | `WithAuth(tamga.SessionCookieAuth{SessionID: id})` — browser/portal only, not relevant to most Go consumers |
| Query parameter | `?token=<token>` | `WithAuth(tamga.QueryParamAuth{Token: token})` |

Every request also carries `Tamga-Version` (`DefaultAPIVersion`, overridable with
`WithAPIVersion`) and, if set, `Tamga-OTP` via `WithOTP`. Requests are bounded by
`DefaultTimeout` (45s) unless you supply your own `*http.Client` via `WithHTTPClient`.

> **License-key auth is off by default server-side.** The license's policy must set
> `authentication_strategy` to `LICENSE` or `MIXED`; the column defaults to `TOKEN`, under which
> every license-key request fails `401 LICENSE_NOT_ALLOWED` (match with `errors.Is(err,
> tamga.ErrLicenseNotAllowed)`). That is a configuration precondition, not a transient failure —
> retrying or re-entering the key will not fix it. Two other 401s come from the same gate:
> `ErrLicenseSuspended`, and `ErrLicenseExpired` (only when the policy's expiration strategy is
> `REVOKE_ACCESS`; under the other three an expired license still authenticates and reports
> `EXPIRED` from a validate call). A license key also authenticates as a narrower role than a
> bearer token: `ResetHeartbeat` and `GenerateOfflineProof` are role-gated above it and return
> `403` unconditionally — use a bearer token with an admin/developer/product/environment role
> for those two.

## Offline verification

Three offline artifacts, all verifiable with no network access once you hold the account's
public key.

### License files (`.lic`)

`CheckOutLicense` downloads the certificate; `(*LicenseFile).Verify` checks the Ed25519
signature, decrypts if the file is encrypted, and enforces the signed expiry.

```go
package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"

	"github.com/tamga-sh/tamga-go"
)

func verifyLicenseFile(pemText string, accountPubKey ed25519.PublicKey, licenseKey string) {
	file, err := tamga.ParseLicenseFile(pemText)
	if err != nil {
		log.Fatal(err)
	}

	// licenseKey is needed only for an "aes-256-gcm+ed25519+v2" file;
	// pass "" for a plain "base64+ed25519+v2" one.
	payload, err := file.Verify(accountPubKey, licenseKey)

	var expired *tamga.ExpiredError
	switch {
	case err == nil:
		fmt.Printf("valid until %d: status=%s\n",
			payload.Claims.ExpiresAt, payload.Data.Attributes.Status)
	case errors.As(err, &expired):
		fmt.Printf("file expired at %d — check out a fresh one\n", expired.ExpiresAt)
	case errors.Is(err, tamga.ErrMissingClaims):
		fmt.Println("pre-v2 file — re-issue it, there is no fallback path")
	case errors.Is(err, tamga.ErrInvalidSignature):
		fmt.Println("forged or corrupted file")
	default:
		log.Fatal(err)
	}
}
```

Set `LicenseFile.Now` to a server-supplied timestamp if you do not want to trust the local clock
(a user winding their system clock back is the obvious way to revive an expired file).

### Machine files (`.machine`)

Same envelope, but the signing algorithm is chosen by the governing license's own `Scheme` —
never by parsing the file's self-declared `alg` — and decryption needs both the license key and
the target machine's fingerprint.

```go
file, err := tamga.ParseMachineFile(pemText)
if err != nil {
	log.Fatal(err)
}

// scheme comes from the license, not the file. Pass tamga.SchemeEd25519Sign
// when the license has no scheme set — that is the server's own default.
// pub must match: ed25519.PublicKey, *rsa.PublicKey, or *ecdsa.PublicKey.
payload, err := file.Verify(tamga.SchemeEd25519Sign, accountPubKey, licenseKey, fingerprint)
if err != nil {
	log.Fatal(err)
}
fmt.Println(payload.Data.Attributes.Fingerprint)
```

`tamga.ParsePKIXPublicKey(der)` is re-exported for loading an RSA/ECDSA key from an SPKI DER
blob without importing `crypto/x509` yourself.

### Offline proofs

A lighter alternative to a full machine checkout: `GenerateOfflineProof` returns a
`"v1x0.<base64>"` string, and `VerifyOfflineProof` checks it against the exact tuple it was
generated for.

```go
machine, proof, err := client.GenerateOfflineProof(ctx, machineID, map[string]any{"cores": 8})
if err != nil {
	log.Fatal(err)
}

err = tamga.VerifyOfflineProof(
	accountRSAPubKey,
	accountID,
	machine.ID,
	machine.Attributes.Fingerprint,
	map[string]any{"cores": 8},
	proof,
)
fmt.Println("proof valid:", err == nil)
```

## Security notes

Every claim below is implemented at the cited location.

- **Offline license files are format v2 only.** `alg` must be `base64+ed25519+v2` or
  `aes-256-gcm+ed25519+v2`, and the signed payload must carry `meta` claims (`iat`, `exp`,
  `jti`, `kid`). A pre-v2 file is rejected with `ErrMissingClaims`
  (`checkout_license.go::(*LicenseFile).Verify`). **This is a behavioral break:** v1 `.lic`
  files fail verification outright, with no fallback path. Re-issue them via `CheckOutLicense`.
- **The signed `exp` is enforced, with a 60-second clock-skew tolerance**
  (`checkout_license.go::clockSkewToleranceSeconds`, applied in `(*LicenseFile).Verify`). The
  tolerance is deliberately small: the local clock is attacker-controlled, so a generous
  allowance is a free extension on every expired file. In v1 the requested `ttl`/`expiry` lived
  only in the response envelope, outside the signature — which made a 24-hour trial file
  cryptographically valid forever.
- **Both file formats derive their AES-256-GCM key with HKDF-SHA256.** License files use
  salt `tamga:license-file-key-v1`, ikm = the license key, info `license-file`
  (`internal/crypto/hkdf.go::DeriveLicenseFileKey`). Machine files use salt
  `tamga:machine-file-key-v1`, ikm = the license key, info = the machine fingerprint
  (`internal/crypto/hkdf.go::DeriveMachineFileKey`), so a machine file cannot be opened anywhere
  but on the machine it was issued for. The earlier license-file transform — raw UTF-8 license
  key bytes zero-padded/truncated to 32 — was removed, not deprecated.
- **The signature covers the base64 *string* bytes of `enc`, not its decoded bytes**
  (`checkout_license.go::(*LicenseFile).Verify`,
  `checkout_machine.go::(*MachineFile).Verify`). Getting this backwards silently accepts forged
  files while still passing a self-generated fixture that repeats the same mistake — there is a
  dedicated regression test for exactly that in `checkout_license_test.go`.
- **Verification is fail-closed and ordered.** The signature is checked before `enc` is
  base64-decoded, decrypted, or parsed as JSON, so attacker-controlled bytes never reach a
  decoder first (`checkout_license.go::(*LicenseFile).Verify`).
- **Machine-file algorithm selection is driven by the license's `Scheme` parameter, never by the
  file's self-declared `alg`** (`checkout_machine.go::verifyMachineFileSignature`). `alg`'s
  suffix is only cross-checked as defence in depth (`checkout_machine.go::schemeAlgSuffix`),
  because `RSA_2048_PKCS1_SIGN` and `RSA_2048_JWT_RS256` share a suffix server-side and cannot be
  told apart from file content. `RSA_2048_JWT_RS256` is rejected up front with
  `ErrSchemeNotSupported`.
- **Offline-proof payloads are serialized byte-exactly.** Keys are sorted alphabetically at every
  nesting level via `map[string]any` (`proof.go::buildOfflineProofPayloadJSON`), and
  `proof.go::serdeCompatMarshal` disables Go's HTML escaping and reverses its unconditional
  U+2028/U+2029 escaping, so a dataset value containing `<`, `>`, `&`, or a Unicode line
  separator still hashes to the same bytes the server signed.
- **HTTP 429 is handled client-side.** `client.go::(*Client).do` retries a throttled request
  transparently: `parseRetryAfter` reads `Retry-After` as delta-seconds, `retryDelay` caps it at
  60s and otherwise uses jittered exponential backoff, and `isRetryable` scopes auto-retry to
  `GET` plus the safe `POST` actions in `client.go::retryablePOSTSuffixes` — `validate`,
  `validate-key`, `check-in`, `check-out`, `ping`, `ping-heartbeat`, `reset-heartbeat`. Creates
  are deliberately excluded: retrying `POST /machines` can burn a second seat, and only you know
  whether that is acceptable. The budget is `DefaultMaxRetries` (3); `WithMaxRetries(0)` hands
  the `*APIError` straight back. The two heartbeat actions need their own entries because
  `/actions/ping-heartbeat` does not end in `/actions/ping` (that is the *process* ping) — and a
  throttled heartbeat that is not retried does not surface as an error, it gets the machine
  culled.
- **Every caller-supplied ID is path-escaped before interpolation**
  (`client.go::escapePathSegment`, `client.go::buildURL`), so an ID containing `/`, `?`, or `#`
  cannot redirect a request or inject query parameters.
- **Server error bodies are never trusted to be well-formed.** A non-JSON:API error page falls
  back to a synthetic `UNKNOWN` `*APIError` carrying only the status (`client.go::mapError`).

`checkout_license.go`, `checkout_machine.go`, `proof.go`, and everything under
`internal/crypto/` carry a mandatory security review before merge — see
[`SECURITY.md`](SECURITY.md).

## Known gaps

- **`.machine` files carry no signed expiry.** Only `.lic` files have the v2 `meta` claims;
  `(*MachineFile).Verify` enforces the signature and the scheme, not a lifetime. A machine
  file's practical bound is the `ttl` requested at checkout plus the fact that decryption
  requires the target fingerprint.
- **`Scope.Version` and `Scope.Checksum` are never sent.** The server rejects the entire
  validate call with `422 SCOPE_NOT_SUPPORTED` the moment either appears, before running any
  validation — so setting them could only break a request that would otherwise have worked.
  `Scope.MarshalJSON` drops both; the fields remain on the struct for source compatibility and
  are documented `Deprecated`. `Scope.Entitlements` and `Scope.Fingerprint`, by contrast, are
  now genuinely enforced: entitlements takes entitlement **codes** (case-insensitive,
  de-duplicated, satisfied by direct or policy-inherited rows; an empty slice asserts nothing),
  and fingerprint matches any machine on the license regardless of heartbeat status.
- **8 of the 24 `ValidationCode` values are unreachable against the current server.** Each
  constant in `validation.go` is marked reachable or not; do not branch on a value that cannot
  come back today. `ENTITLEMENTS_MISSING` and `FINGERPRINT_SCOPE_MISMATCH` are reachable now.
- **`GET /licenses/{id}/entitlements` is not paginable.** The listing unions the license's
  direct entitlements with the ones inherited from its policy, which a single keyset cursor
  cannot describe, so the server accepts `page[after]` and ignores it — the same first page
  comes back forever. `ListEntitlements` never sends `page[after]` and always returns
  `NextCursor == nil`; a license with more than 100 effective entitlements cannot be enumerated
  in full. `ListComponents` is unaffected — keyset pagination genuinely works there.
- **Both list routes silently return 25 rows if no `limit` is sent**, with no page metadata to
  reveal the truncation. `ListComponents`/`ListEntitlements` send an explicit `limit=100` (the
  server maximum) when `ListOptions.Limit` is unset.
- **`Entitlement.Attributes.Inherited`** reports whether the license holds an entitlement
  through its policy. It is only present on the license-scoped list route, hence `*bool` — `nil`
  means "the server did not say", not `false`. An inherited entitlement cannot be detached, and
  `GetEntitlement` returns `404` for it, so list-then-get-each is not a valid pattern here.
- **`QuickValidate` does not always record the validation.** The server skips the
  `last_validated_at` write whenever the request carries an `Origin` header, and the response is
  byte-identical either way. This SDK never sets `Origin`, but a proxy or service mesh can — and
  a license whose `last_validated_at` stays NULL reports `INACTIVE` and keeps firing
  check-in-overdue webhooks. Use `ValidateByID` when the write must be guaranteed.
- **Machine `Memory` and `Disk` are MEGABYTES, not bytes** — on both `MachineAttributes` and
  `CreateMachineOptions`. Reporting 16 GiB as `17179869184` rather than `16384` inflates the
  license's memory counter by 1048576× and trips `MEMORY_LIMIT_EXCEEDED` on its next activation.
- **The machine heartbeat window is a hardcoded 600s**, not driven by the policy's
  `heartbeat_duration` field despite that field existing (`machine.go`, `HeartbeatStatus`).
  `DefaultHeartbeatInterval` is window/3.
- **`HasEntitlement` fetches exactly one page** (100 entitlements, the server's max page size)
  and caches codes in memory for 60s. That page is also the ceiling — the route cannot be
  paginated, so a `false` result is authoritative only for licenses holding at most 100
  effective entitlements. Do not gate features on it above that.
- **Offline-proof datasets should stick to integers, strings, and typical floats.**
  `serdeCompatMarshal` closes the escaping gaps between Go and the server's JSON encoder, but
  not float formatting at extreme magnitudes (e.g. `1e20`), where the two can pick different
  decimal-vs-scientific cutoffs — see `proof.go::GenerateOfflineProof`.
- **No auto-update / release-checking API yet.** Earlier revisions of this file said the
  endpoint 500s on every call; that was wrong. `GET /releases/actions/upgrade` is live and
  public — it is simply not wrapped by this SDK yet. Artifact download has a route too, but no
  role currently holds the `artifact.download` permission, so it returns 403 for every real
  client until that is fixed server-side.
- **No RFC 9421 response-signature verification** — no API response is ever signed today, so
  there is nothing to verify.

## Documentation

- [pkg.go.dev/github.com/tamga-sh/tamga-go](https://pkg.go.dev/github.com/tamga-sh/tamga-go) —
  generated API reference.
- [tamga.sh](https://tamga.sh) — product documentation and the API protocol reference.
- [`examples/`](examples) — runnable programs for every major flow.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup and PR expectations.
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting and the offline-format compatibility
  warning.

## License

MIT — see [LICENSE](LICENSE).
