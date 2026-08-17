# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tamga-go` is the official Go SDK for Tamga (license activation, offline verification, machine
fleet management). Single module, flat top-level `tamga` package — import path equals module
path (`github.com/tamga-sh/tamga-go`, no `pkg/` nesting). The protocol source of truth is the
Tamga API server's own SDK protocol reference (`docs/sdk.md` in the server repo, which is
private) — every field name, endpoint path, and enum value in this SDK is transcribed from that
file, not paraphrased. Where it disagrees with anything else, it reflects actual runtime
behavior and wins.

**Current state: feature-complete and released (latest: `v1.2.0`).** Client/transport, license
validate/check-in, machine/component/process management + heartbeats, entitlements, error model,
policy enums, license/machine checkout crypto, offline proof, HTTP 429 retry/backoff,
docs/examples, and CI/release automation are all implemented and tested.

Resource/relationship IDs are plain Go `string`s throughout, not a dedicated UUID type — see
`license.go`'s `License` doc comment for why (this repo's single-external-dependency constraint
on `golang.org/x/crypto`).

## Architecture

```
tamga-go/
├── go.mod                     # module github.com/tamga-sh/tamga-go, go 1.22
├── go.sum
├── doc.go                      # package doc comment + file map
├── client.go                   # Client struct, functional options, 429 retry/backoff
├── transport.go                # AuthTransport + 5 concrete transports
├── license.go                  # License resource, Validate*/CheckIn, Scope
├── machine.go                  # Machine/Component/Process CRUD + heartbeats
├── validation.go               # ValidationCode string enum (24 values)
├── entitlement.go              # Entitlement resource, HasEntitlement + cache
├── policy.go                   # LicenseScheme/OverageStrategy/heartbeat enums
├── checkout_license.go         # .lic parse/verify — Ed25519 + HKDF AES key, format v2
├── checkout_machine.go         # .machine parse/verify — multi-scheme + HKDF
├── proof.go                    # offline proof generate/verify — byte-exact RSA
├── errors.go                   # JSON:API Error/ErrorResponse, APIError Is/As
│
├── internal/crypto/            # not importable outside this module
│   ├── ed25519.go, rsa.go, ecdsa.go, aesgcm.go   # stdlib wrappers
│   └── hkdf.go                                   # golang.org/x/crypto/hkdf wrapper —
│                                                 # both license- and machine-file keys
│
├── *_test.go                    # co-located per Go convention, one per root file
├── internal/crypto/*_test.go
├── testdata/                    # fixtures land alongside real implementation
│
├── .golangci.yml, justfile
├── README.md / CONTRIBUTING.md / LICENSE
├── release-please-config.json / .release-please-manifest.json
└── .github/workflows/ci.yml, release.yml, dependabot.yml
```

**Why `internal/crypto/` and not root-level crypto helpers:** none of these primitives are meant
to be part of the public API — a consumer calls `LicenseFile.Verify()`, never a primitive
directly. Go's `internal/` import restriction enforces that boundary at compile time.

## Dev Commands

```bash
just test    # go test ./ ./internal/... -race -cover (excludes examples/, which has no tests)
just lint    # golangci-lint run ./...
just fmt     # gofmt -l -w . && goimports -w .
just build   # go build ./...
just check   # fmt-check + lint + test — run before opening a PR
```

**`just check` is weaker than CI.** CI additionally runs the full Go 1.22/1.23 × ubuntu/macos/
windows matrix (`-race` only on the ubuntu leg) and gates on `go-test-coverage@v2
-fail-under=80` reading `coverage.out` — a locally green `just check` does not guarantee CI is
green if you've only run one Go version or skipped `-race`.

**First-time setup**: `go mod download` — no external services, no Docker, no database. This SDK
is a pure HTTP client library; it never talks to anything but the Tamga API it's configured
against (and in tests, an `httptest.Server`).

## GOTCHAS

Pulled from the server protocol reference's "Known Server-Side Gaps" section — only the items
that actually constrain this repo's scope are listed; several gaps there are server-internal
(analytics storage, edition gating) and don't apply to any SDK.

- **Do not build the auto-update/release-checking feature.** `GET /releases/actions/upgrade`
  joins a table that doesn't exist and 500s on every real call; even once fixed server-side, it
  returns no download URL, so a second endpoint would still be needed and doesn't exist. This is
  a hard non-goal for v1, not a "coming soon" stub — don't scaffold a `releases.go` for it.
- **429 handling already ships — extend it, don't re-invent it.** `client.go`'s `do()` retries a
  throttled request transparently: `parseRetryAfter` reads `Retry-After` as delta-seconds,
  `retryDelay` caps it at 60s and otherwise falls back to jittered exponential backoff, and
  `isRetryable` scopes auto-retry to `GET` plus the five safe `POST` actions in
  `retryablePOSTSuffixes` (`validate`, `validate-key`, `check-in`, `check-out`, `ping`). Creates
  are deliberately excluded — retrying `POST /machines` can burn a second seat. Budget is
  `DefaultMaxRetries` (3), overridable with `WithMaxRetries`; `0` hands the `*APIError` straight
  back to the caller.
- **Model all 24 `ValidationCode` values, but only 14 are reachable today** (`validation.go`
  already encodes this — see its doc comment for the exact split). Do not write example code or
  documentation implying `BANNED`, `ENTITLEMENTS_MISSING`, `HEARTBEAT_DEAD`, or the other ⛔
  values can come back from a live call — they can't, yet.
- **`Scope.Entitlements`/`Fingerprint`/`Version`/`Checksum` are parsed but silently ignored
  server-side.** Model them on the `Scope` struct for forward-compatibility (they're in the
  wire format), but never advertise them in docs/examples as functioning constraints — a caller
  who sets `Scope.Version` today gets no enforcement and no error telling them so.
- **Auth is not enforced on license or machine endpoints server-side.** Still always send
  `Authorization: License <key>` (the SDK's default transport) — this is forward-compatible with
  enforcement landing later, and costs nothing today since nothing checks it.
- **Policy `overage_strategy`/`heartbeat_resurrection_strategy` defaults are not real enum
  values.** Freshly created policies default to `"DENY_ACCESS"` / `"NO_RESURRECTION"` — neither
  matches a real `OverageStrategy`/`HeartbeatResurrectionStrategy` variant. The
  `EffectiveOverageStrategy`/`EffectiveResurrectionStrategy` helpers (`policy.go`, once
  implemented) must fall back to `NO_OVERAGE`/`NO_REVIVE` for these, matching server behavior —
  do not surface the raw string as if it meant "deny everything," which is what the field name
  implies and is not what actually happens.
- **No RFC 9421 HTTP message signing support.** Dead code server-side (`sign_response*` have no
  call sites); no API response is ever signed today. Do not add response-signature verification.
- **Do not implement a `Tamga-Environment` request header.** Planned EE feature; no server code
  path reads it yet.

## Critical Dependency Notes

**stdlib covers every cryptographic scheme this SDK verifies except HKDF.** `crypto/ed25519`,
`crypto/rsa`, `crypto/ecdsa`, and `crypto/cipher`+`crypto/aes` are all sufficient for the
Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256/AES-256-GCM surface in `checkout_license.go`,
`checkout_machine.go`, and `proof.go`. Only HKDF — which derives *both* the license-file and the
machine-file AES key (`internal/crypto/hkdf.go`) — has no stdlib implementation, so
`golang.org/x/crypto/hkdf` is this module's **one and only** external dependency. Do not add a second dependency for a primitive stdlib already covers; if a future
change seems to need one, that's a signal to re-check whether stdlib already has it under a
name that isn't obvious (e.g. `crypto/subtle` for constant-time comparisons).

`golang.org/x/crypto` is pinned to **v0.33.0**, not latest — v0.34.0+ raises the module's own
`go` directive to 1.23, which would force this SDK's minimum Go version up a full point release
for no functional gain (HKDF's API hasn't changed). Bumping past v0.33.0 requires deliberately
deciding to drop Go 1.22 support, not a routine dependency update; if Dependabot proposes it,
don't merge it reflexively.

For context on how the sibling Tamga SDKs handle their own crypto dependency, each hand-written
SDK has made — or will make — its own explicit, documented exception here rather than reaching
for the ecosystem default: `tamga-rust`/`tamga-c` use `aws-lc-rs` (the `rsa` crate is banned in
that repo — RUSTSEC-2023-0071, an unpatched Marvin timing attack); `tamga-js` uses
`@noble/curves` + `@noble/hashes` for an audited, zero-dependency-tree pure-JS implementation
rather than Node's `crypto` module (which lacks Ed25519 PSS/some scheme coverage in older
runtimes); `tamga-dotnet` is expected to carry an `NSec.Cryptography` exception rather than
`System.Security.Cryptography` for the same class of gap-coverage reason. Go's own stdlib being
sufficient here — minus HKDF — is this repo's version of that same design conversation; it just
resolves differently because Go ships more of the relevant primitives natively than the other
runtimes do. The takeaway that generalizes across all of them: don't assume a language's
"default" crypto library covers this SDK family's full scheme list — verify per algorithm before
committing to it, the way this file's own note on `golang.org/x/crypto` pinning above does.

## Testing

- Coverage gate: **80%**, enforced by CI via `vladopajic/go-test-coverage@v2
  -fail-under=80` reading `go test -coverprofile=coverage.out -covermode=atomic`. Run the same
  locally with `just test` (add `-coverprofile=coverage.out` manually to inspect the exact
  number `just test`'s plain `-cover` summary doesn't show).
- Table-driven tests are the house style (see `~/.claude/rules/testing.md` / `ecc:golang-testing`
  — RED/GREEN/REFACTOR, write the test before the implementation).
- `checkout_license_test.go`, `checkout_machine_test.go`, and `proof_test.go` each carry a
  **negative regression test that is more important than its happy-path counterpart**: a test
  that deliberately reintroduces the section's central bug (signing over decoded bytes instead
  of the base64 string; accepting `RSA_2048_JWT_RS256`; reconstructing the offline-proof JSON
  with a different field order) and asserts `Verify()` still rejects it. A green test suite that
  is missing these regression cases has not actually proven the verifier is correct — a
  self-authored fixture that repeats the same bug as the implementation will pass a naive
  round-trip test while silently accepting forged real-world files.
- Run one file: `go test -run TestX ./...` or scope by package: `go test ./internal/crypto/...`.

## Branch & Commit Convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/) (`feat: …`, `fix: …`,
etc.) — `release-please` (`.github/workflows/release.yml`) derives version bumps and the
changelog directly from these, and for a Go module the resulting tag *is* the entire release
(no separate publish step).
