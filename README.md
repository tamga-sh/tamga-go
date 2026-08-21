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

Keep it alive with `NewHeartbeatScheduler(client, machine.ID, interval)` and
`(*HeartbeatScheduler).Run(ctx)`, which pings until the context is canceled. Size `interval`
from the policy rather than from `DefaultHeartbeatInterval`, which assumes the server's 600s
fallback window:

```go
interval, err := client.HeartbeatIntervalForLicense(ctx, license.ID)
if err != nil {
	interval = tamga.DefaultHeartbeatInterval // 600s fallback / 3
}
```

> **The loop must not stop on any `HeartbeatStatus`.** The only terminal signal from a ping is a
> **404 `NOT_FOUND`**, which means the row is gone — hang re-activation off
> `errors.Is(err, tamga.ErrNotFound)` and off nothing else. `Run` is written that way: it never
> inspects the status, and only context cancellation ends its loop.
>
> **`DEAD` is not reachable from the heartbeat routes.** `PingHeartbeat` writes
> `last_heartbeat_at = NOW()` and then derives the status from that same timestamp, so its
> response is always `ALIVE` or `RESURRECTED`; `ResetHeartbeat` and `CreateMachine` both answer
> `NOT_STARTED`. A `case DEAD` branch written against a ping is dead code. It **is** reachable
> from five routes — `GetMachine`, `ListMachines`, `CheckOutMachine` (on `MachinePayload.Data`,
> after `MachineFile.Verify`), `GenerateOfflineProof` (on the `*Machine` it returns) and
> `UpdateMachine` — so handle `DEAD` there. The durable rule is not write-versus-read but
> whether the response was built off a `last_heartbeat_at` the same request just wrote:
> `UpdateMachine` is a write that touches none of the heartbeat columns, which is exactly why it
> can report `DEAD`. Wherever it appears it means only that the last ping is
> older than the window, **not** that the machine was culled: the server never looks at the
> policy's `require_heartbeat` flag when computing it, and the culling job early-returns unless
> that flag is set — which it is **not**, by default. A machine can report `DEAD` forever with
> its row and its seat intact.
>
> ```go
> hbCtx, cancel := context.WithCancel(ctx)
> defer cancel()
> scheduler := tamga.NewHeartbeatScheduler(client, machine.ID, 0,
> 	tamga.WithHeartbeatOnTick(func(m *tamga.Machine, err error) {
> 		if errors.Is(err, tamga.ErrNotFound) {
> 			// The row is genuinely gone — this, and only this, is the
> 			// re-activation trigger.
> 			cancel()
> 			return
> 		}
> 		// Log m.Attributes.HeartbeatStatus if you like, but never branch
> 		// the loop on it — no status is a stop condition.
> 	}))
> go scheduler.Run(hbCtx)
> ```

`examples/` holds runnable programs for validation, check-in, license/machine file verification,
the machine lifecycle, and entitlement checks — `go run ./examples/validate -h` to start.

### Reads, cleanup and the rest of the surface

| Call | Route | Notes |
|---|---|---|
| `GetMachine(id)` | `GET /machines/{id}` | Joins the policy, so `HeartbeatStatus` and `NextHeartbeatAt` are real. Can report `DEAD`. |
| `ListMachines(opts)` | `GET /machines` | **Offset**-paginated (`MachinePage.Page`). Filters: license/owner/group/platform plus free-text `Query`. **No fingerprint filter.** |
| `UpdateMachine(id, opts)` | `PATCH /machines/{id}` | Enveloped body. Omitted fields are unchanged and cannot be cleared to NULL. Heartbeat fields on the response use the 600s fallback. |
| `FindMachineByFingerprint(licenseID, fp)` | — | `filter[q]` narrowing plus a client-side exact match, scoped to one license. |
| `ActivateMachineIdempotent(opts, scope)` | — | `ActivateMachine`, but a `409 FINGERPRINT_TAKEN` is recovered into the existing machine instead of raised. |
| `ListMachineProcesses(id, opts)` | `GET /machines/{id}/processes` | Keyset, unlike its parent collection. |
| `DeleteProcess(id)` | `DELETE /processes/{id}` | The only cleanup there is — nothing reaps process rows server-side. |
| `GetLicense(id)` | `GET /licenses/{id}` | A read, not a verdict; does not touch `last_validated_at`. |
| `GetLicensePolicy(id)` | `GET /licenses/{id}/policy` | The policy read that works under a license key. |
| `GetPolicy(id)` | `GET /policies/{id}` | Needs `policy.read`; **403s under a license key**. |
| `HeartbeatIntervalForLicense(id)` | — | The policy's window / 3, ready for `NewHeartbeatScheduler`. |
| `CheckUpgrade(opts)` | `GET /releases/actions/upgrade` | Four required query params; `offered == false` is **not** "up to date". |
| `ListReleaseArtifacts(releaseID, opts)` | `GET /releases/{id}/artifacts` | Keyset. Does **not** apply the release read gate — listing an artifact is not evidence it can be downloaded. |
| `GetArtifact(id)` | `GET /artifacts/{id}` | Metadata only; `RedirectURL` is always nil here. |
| `ArtifactDownloadURL(id, opts)` | `GET /artifacts/{id}/actions/download` | Sends `?redirect=false` and never follows a redirect. Returns the presigned URL. |
| `DownloadArtifact(id, opts)` | — | The URL above, fetched from storage with **no** credentials attached. |
| `Health()` | `GET /v1/health` | Sent with **no credential** and no account prefix; flat body, not JSON:API. |

Re-activating a machine that is already registered is a `409 FINGERPRINT_TAKEN` from
`ActivateMachine`, because the server checks uniqueness before its quota limits so that a
re-activation is not misreported as a limit failure. `ActivateMachineIdempotent` turns that into
a no-op:

```go
machine, meta, err := client.ActivateMachineIdempotent(ctx, opts, nil)
```

It looks the existing machine up scoped to the caller's own license and returns it. When the
fingerprint is taken on a **different** license — possible under `UNIQUE_PER_POLICY` or
`UNIQUE_PER_ACCOUNT` — the lookup finds nothing and the original `409` is re-raised rather than
resolved: adopting that row would attach the caller to a seat its license does not own, and a
machine resource carries no `license_id` with which it could ever notice. Unlike
`ActivateMachine`, an over-limit verdict on the recovery path does **not** delete the machine —
it was already there.

## Artifacts

Once `CheckUpgrade` reports that a newer release is available, the artifacts are its uploaded
files:

```go
page, err := client.ListReleaseArtifacts(ctx, release.ID, tamga.ListOptions{})
artifact, err := client.GetArtifact(ctx, page.Items[0].ID)

body, err := client.DownloadArtifact(ctx, artifact.ID, tamga.DownloadArtifactOptions{
    TTL: 10 * time.Minute, // optional; [1 minute, 1 week]
})
defer body.Close()
```

**Do not follow the download redirect yourself.** `GET /artifacts/{id}/actions/download` answers
`303 See Other` pointing at a short-lived presigned storage URL, and an HTTP client that follows
it can carry the request's `Authorization` header — your raw license key — to a host that is not
the Tamga API. Go's standard library drops `Authorization` only when the redirect leaves the
original *domain*, and still forwards it to a subdomain; every other header, `Tamga-OTP`
included, is forwarded unconditionally. `ArtifactDownloadURL` sends `?redirect=false` **and**
routes the request through a redirect-suppressing copy of the configured HTTP client, so a
server or proxy that redirects anyway cannot cause one to be followed. `DownloadArtifact` then
fetches the returned URL with no credentials at all.

Nothing in that path authenticates the bytes. Verify the download against
`ArtifactAttributes.Checksum` before installing or executing anything.

A `403` from the download action is **not** necessarily an auth misconfiguration: the handler
enforces the owning release's read gate as well as the `artifact.download` permission, so a
`CLOSED` release's binary is refused even to a caller that holds it — and the same artifact is
still visible through `ListReleaseArtifacts` and `GetArtifact`, which do not apply that gate.

`ArtifactAttributes` carries the same two-rules-at-once serialization trap as
`ReleaseAttributes`: the struct is camelCased, so `redirect_url` is `redirectUrl` on the wire,
but `created_at`/`updated_at` carry explicit per-field renames that override it and arrive as
the bare `created` and `updated`. Applying either rule uniformly breaks the other half.

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

Same envelope and the same v2 rules, with two differences. The signing algorithm is chosen by
the governing license's own `Scheme` — never by parsing the file's self-declared `alg` — and
decryption needs both the license key and the target machine's fingerprint.

`Alg` is a three-part string, `<encoding>+<signing suffix>+v2`: `base64+ed25519+v2`,
`aes-256-gcm+rsa-pss-sha256+v2`, and so on. The `+v2` marker is mandatory, exactly as it is for
`.lic`.

```go
file, err := tamga.ParseMachineFile(pemText)
if err != nil {
	log.Fatal(err)
}

// scheme comes from the license, not the file. Pass tamga.SchemeEd25519Sign
// when the license has no scheme set — that is the server's own default.
// pub must match: ed25519.PublicKey, *rsa.PublicKey, or *ecdsa.PublicKey.
payload, err := file.Verify(tamga.SchemeEd25519Sign, accountPubKey, licenseKey, fingerprint)

var expired *tamga.ExpiredError
switch {
case err == nil:
	// Claims.ExpiresAt is 0 when the checkout was made without a ttl —
	// that file genuinely never expires.
	fmt.Println(payload.Data.Attributes.Fingerprint, payload.Claims.ExpiresAt)
case errors.As(err, &expired):
	fmt.Printf("file expired at %d — check out a fresh one\n", expired.ExpiresAt)
case errors.Is(err, tamga.ErrInvalidSignature):
	fmt.Println("forged or corrupted file")
default:
	log.Fatal(err)
}
```

Set `MachineFile.Now` to a server-supplied timestamp for the same reason you would set
`LicenseFile.Now`.

`tamga.ParsePKIXPublicKey(der)` is re-exported for loading a key from an SPKI DER blob without
importing `crypto/x509` yourself — but note that **the API does not publish every account key as
SPKI**, so it is not a general-purpose loader. An ECDSA P-256 key is a raw 65-byte uncompressed
SEC1 point (`0x04 || X || Y`) that no `crypto/x509` entry point can read; an RSA-2048 key may be
PKCS#1 `RSAPublicKey` DER (270 bytes) or SPKI (294 bytes) depending on the endpoint that served
it; an Ed25519 key is the raw 32 bytes. `examples/checkout_machine/main.go::parsePublicKey`
handles all four cases and is the copy-paste source.

### Key rotation (`VerifyWithKeySet`)

When an account rotates its Ed25519 signing key, a file signed **before** the rotation is still
authentic — but against the single current key it fails with `ErrInvalidSignature`, the same
error a forgery produces. A paying customer gets locked out and the error points support at the
wrong problem.

`VerifyWithKeySet` verifies against every key the account has ever held, so the two outcomes stop
being the same error:

```go
// One call, cacheable for the life of the process: a rotation adds a key,
// it never invalidates the ones already there.
keys, err := client.GetSigningKeySet(ctx)
if err != nil {
	log.Fatal(err)
}

verified, err := file.VerifyWithKeySet(keys, licenseKey)

var unknownKey *tamga.UnknownSigningKeyError
switch {
case err == nil:
	if verified.Key.IsRetired() {
		// Authentic, and issued before the last rotation. Nothing is wrong
		// with it — but this client is due a fresh checkout.
		log.Printf("verified under retired key %s", verified.Key.ID)
	}
	fmt.Println(verified.Payload.Data.Attributes.Status)

case errors.Is(err, tamga.ErrUnknownSigningKey):
	// NOT a forgery. The file names a key this set does not hold, which is
	// what a genuine pre-rotation file looks like against a stale set.
	errors.As(err, &unknownKey)
	log.Printf("stale key set: file names %s, we hold %v", unknownKey.KeyID, unknownKey.Available)

case errors.Is(err, tamga.ErrSigningKeyNotPublished):
	// The account that signed this has published no Ed25519 key at all, so
	// it signed with the id of the empty string. Refreshing cannot fix it.
	log.Print("server published no signing key; an operator must rotate one in")

case errors.Is(err, tamga.ErrInvalidSignature):
	// The key it names IS in the set and rejects these bytes. Refuse it.
	log.Print("tampered file")
}
```

`(*MachineFile).VerifyWithKeySet` takes the same set alongside the scheme, license key and
fingerprint.

**Reading the key set without the API.** `GET /signing-keys` authorizes on `account.read`, which
a license-key credential does not hold — an embedded client gets `403` there unconditionally.
Pin the public keys in your binary instead:

```go
keys, err := tamga.NewSigningKeySetFromPublicKeys(currentPubKeyB64, previousPubKeyB64)
```

That path is strict on purpose: a mistyped key fails at startup rather than reporting every
genuine file in the field as signed by an unknown key. `tamga.KeyID(publicKeyB64)` computes the
`kid` a file signed with that key will name — note it hashes the **base64 string**, never the 32
decoded bytes.

Both existing entry points are untouched: `Verify` keeps its exact signature and behaviour and
remains the right call when you hold one key and know it.

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
- **Machine files are format v2 only too, on the same terms.** `alg` must end in `+v2`
  (`checkout_machine.go::parseMachineFileAlg`) — the check is an equality test on the last
  `+`-delimited segment, not a substring search, so `+v3` and `+v2junk` are refused as well —
  and the payload's `meta` claims are surfaced on `MachinePayload.Claims`. The signed `exp` is
  enforced with the same `clockSkewToleranceSeconds` and the same `*ExpiredError` as the license
  path, and `MachineFile.Now` accepts a trusted timestamp for the same reason. `exp` is optional
  server-side — a checkout made without a `ttl` produces a file with no `exp` that genuinely
  never expires, so its absence is not an error. **This is a behavioral break:** a v1 `.machine`
  file, and any file that expired while nothing was checking, now fails.
- **An encrypted machine file's `enc` is `"<nonce_b64>.<ciphertext_b64>"`** — two separately
  base64-encoded halves, decoded independently (`checkout_machine.go::splitEncryptedEnc`), with
  the GCM tag already appended to the ciphertext half. It is *not* a single base64 blob of
  `nonce||ciphertext||tag`; an encrypted `.lic` file is, and the two must not be conflated. The
  split happens only after the signature over the whole `enc` string has passed.
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
  throttled heartbeat that is not retried does not surface as an error, it silently drops the
  machine into `DEAD` (and, under a `require_heartbeat` policy, eventually gets it culled).
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
- **The keyset list routes silently return 25 rows if no `limit` is sent**, with no page
  metadata to reveal the truncation. `ListComponents`, `ListEntitlements` and
  `ListMachineProcesses` therefore send an explicit `limit=100` (the server maximum) when
  `ListOptions.Limit` is unset. `ListMachines` is the exception in the other direction: it is
  **offset**-paginated and does report `meta.page{number,size,total,totalPages}` (surfaced as
  `MachinePage.Page`), so nothing is truncated silently there — but it takes `page[number]` and
  `page[size]` rather than a cursor, and `MachinePage` has no `NextCursor`. The machine
  collection and its own sub-collections genuinely disagree; do not unify them.
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
- **The machine heartbeat window is policy-driven, and `DefaultHeartbeatInterval` still is
  not.** The server judges a machine against its policy's `heartbeat_duration` when that field
  is set, and falls back to 600s only when it is null. `DefaultHeartbeatInterval` is window/3
  computed against that 600s fallback, so on a policy with a shorter `heartbeat_duration` it
  pings too slowly and machines read `DEAD` between ticks. Read the real window with
  `HeartbeatIntervalForLicense` (or `GetLicensePolicy` plus
  `PolicyAttributes.HeartbeatInterval`) and pass the result to `NewHeartbeatScheduler`.
  Do **not** derive it from `MachineAttributes.NextHeartbeatAt`: that field is computed against
  the policy on `GetMachine`/`ListMachines`/`CheckOutMachine`/`GenerateOfflineProof` and against
  the 600s fallback on `CreateMachine`/`PingHeartbeat`/`ResetHeartbeat`/`UpdateMachine`, and a
  caller holding a `Machine` cannot tell which kind it has. The route a scheduler naturally
  calls is the wrong one.
- **Heartbeat intervals are floored at one second.** `NewHeartbeatScheduler`,
  `NewProcessHeartbeatScheduler` and `PolicyAttributes.HeartbeatInterval` all raise a *positive*
  interval below 1s up to exactly 1s. Passing `0` still means "use the default" and is
  unchanged; what changed is that `500 * time.Millisecond` now becomes `1 * time.Second` instead
  of being passed through. `time.NewTicker` only panics on a non-positive interval, so a
  sub-second one used to sail through — and `time.NewTicker(time.Millisecond)` ticks a thousand
  times a second, which through this SDK's own scheduler measures at **999 ping requests per
  second**. It is easy to land there by accident, because these parameters are `time.Duration`
  while the policy's `heartbeat_duration` counts whole *seconds*. No policy-expressible window
  is lost to the floor: `heartbeat_duration` 1 and 2 are still served (their windows divide to
  333ms and 666ms and are raised to 1s), just with less slack for a dropped ping. A stored
  `heartbeat_duration` of `0` is a zero-length window no ping rate can hold at all, and keeps
  falling back to the 600s default rather than pinging every second to fail.
- **`GET /policies/{id}` is not callable with a license key.** It authorizes on `policy.read`,
  which is absent from the `LicenseToken` role's permission set, so `GetPolicy` returns `403`
  unconditionally under `WithLicenseKey` — no policy setting changes that. `GetLicensePolicy`
  returns the identical `policies` resource through `GET /licenses/{id}/policy`, which
  authorizes on `license.read`; that is the one an embedded client should call.
- **`GET /licenses/{id}` is not license-scoped, and returns the key in plaintext.** The server
  applies `require_license_scope` to exactly five routes — validate, validate-key,
  quick-validate and both check-outs — and no machine or license read is among them, while a
  `LicenseToken` holds `machine.read`/`machine.update`/`machine.delete` by default. A license
  key can therefore read, patch and delete any machine in the account and read any license's
  `attributes.key`. This is a server-side exposure the SDK cannot fix; it is documented here
  rather than papered over.
- **Nothing server-side reaps a process row.** The reaper that would delete a process whose 30s
  heartbeat window lapsed is dead code, and `ProcessAttributes` carries no heartbeat status that
  would reveal one had gone stale, so a row created by `CreateProcess` lives until a client
  deletes it — and every surviving row counts against the policy's `max_processes`. Pair every
  `CreateProcess` with a `DeleteProcess`; `(*ProcessHeartbeatScheduler).Dispose(ctx)` is that
  call wired to the process a scheduler was already pinging.
- **`HeartbeatStatus == DEAD` is route-dependent — and never meant deletion on any of them.**
  The heartbeat routes cannot report it: `PingHeartbeat` writes `last_heartbeat_at = NOW()` and
  only then derives the status from it, so it answers `ALIVE` or `RESURRECTED`, and
  `ResetHeartbeat`/`CreateMachine` answer `NOT_STARTED` — a `case DEAD` branch written against a
  ping is dead code. Five routes do report it: `GetMachine`, `ListMachines`, `CheckOutMachine`
  (on `MachinePayload.Data`, after `MachineFile.Verify`), `GenerateOfflineProof` (on the
  `*Machine` it returns) and `UpdateMachine`. The first four also join the policy, so their
  `HeartbeatStatus` and `NextHeartbeatAt` are measured against the real `heartbeat_duration`
  rather than the 600s fallback; `UpdateMachine` is the counterexample that keeps the rule
  honest — a write that touches none of the heartbeat columns, so it judges an untouched
  timestamp and can say `DEAD`, while its `UPDATE … RETURNING` omits the policies join and lands
  on the fallback for both fields. Read the rule as being about which columns a statement
  touched, not about the HTTP verb. Wherever it
  appears, `DEAD` reports staleness, not deletion: the server computes it purely from
  `last_heartbeat_at` versus the window and never consults `require_heartbeat`, and the culling
  job early-returns unless that column is true — it **defaults to false**, so on a default policy
  nothing is ever culled and `heartbeat_cull_strategy`/`heartbeat_resurrection_strategy` are both
  dead letters. The scheduler rule is status-independent: **never stop on any status.**
  `HeartbeatScheduler.Run` does not, and only context cancellation ends its loop. The only
  terminal signal is a **404 `NOT_FOUND` from the ping itself**
  (`errors.Is(err, tamga.ErrNotFound)`) — trigger re-activation from that.
- **`HasEntitlement` fetches exactly one page** (100 entitlements, the server's max page size)
  and caches codes in memory for 60s. That page is also the ceiling — the route cannot be
  paginated, so a `false` result is authoritative only for licenses holding at most 100
  effective entitlements. Do not gate features on it above that.
- **Offline-proof datasets should stick to integers, strings, and typical floats.**
  `serdeCompatMarshal` closes the escaping gaps between Go and the server's JSON encoder, but
  not float formatting at extreme magnitudes (e.g. `1e20`), where the two can pick different
  decimal-vs-scientific cutoffs — see `proof.go::GenerateOfflineProof`.
- **`CheckUpgrade`'s "no update" answer is deliberately ambiguous.** `GET
  /releases/actions/upgrade` takes four **required** query parameters — `product` (a UUID, not a
  code), `platform`, `filetype` (one word, not a filename) and `version` — plus optional
  `channel` and `constraint`; omitting `channel` matches every channel including alpha and dev,
  and omitting `constraint` means patch-only. A `204` means either "no newer release matches"
  **or** "a newer release exists and this license is not entitled to move to it", and the server
  refuses to distinguish them so that a refusal cannot leak a release's existence. `CheckUpgrade`
  therefore returns `(release, offered, error)`; report `offered == false` as "no update is
  available to you", never as "you are on the latest version". A suspended license is the one
  explicit refusal — `403`, checked before the `204` branch is reached.
- **Artifact publishing is out of scope; artifact *download* no longer is.** This bullet used to
  say the download route returned 403 for every real client because no role held
  `artifact.download`. That was true when it was measured and is not true now: the server granted
  `artifact.read` and `artifact.download` to the license-token role and routed a real handler, so
  `ListReleaseArtifacts`, `GetArtifact`, `ArtifactDownloadURL` and `DownloadArtifact` all work
  under a license key. `artifact.create`/`update`/`delete` are still absent from that role, so
  creating, updating, deleting and uploading an artifact remain unwrapped — those are
  build-pipeline calls made with a product or environment token.
- **A machine's `group` and `owner` sub-resources are not wrapped either.**
  `GET|PATCH /machines/{id}/{group,owner}` return `groups` and `users` resource types this SDK
  does not model, and reassigning a machine's owner or group is an admin-console concern rather
  than an embedded-client one. A deliberate scope decision, not an oversight.
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
