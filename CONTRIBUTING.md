# Contributing to tamga-go

## Dev setup

```bash
git clone https://github.com/tamga-sh/tamga-go.git
cd tamga-go
go mod download
just check
```

Requires Go 1.22+ and [`just`](https://github.com/casey/just). No external services are needed
to build or run the test suite — this SDK talks to the Tamga API over plain HTTP and has no
local infra dependency.

## Common commands

```bash
just test    # go test ./ ./internal/... -race -cover (excludes examples/, which has no tests)
just lint    # golangci-lint run
just fmt     # gofmt -l -w . && goimports -w .
just build   # go build ./...
just check   # fmt-check + lint + test — run this before opening a PR
```

See the [`justfile`](justfile) for exact recipe contents.

## PR expectations

- Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages
  (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`) — `release-please`
  derives the changelog and version bump from these.
- `just check` must pass locally before requesting review. CI (`.github/workflows/ci.yml`) runs
  the same lint/test/coverage gate across the Go 1.22/1.23 × ubuntu/macos/windows matrix, plus
  `-race` on the ubuntu leg and an 80% coverage floor via `go-test-coverage` — treat CI as
  authoritative, not `just check` alone, if the two ever disagree.
- Sections implementing checkout or offline-proof cryptography
  ([`checkout_license.go`](checkout_license.go), [`checkout_machine.go`](checkout_machine.go),
  [`proof.go`](proof.go), and everything under `internal/crypto/`) require a `security-reviewer`
  pass before merge — see [`docs/plans/tamga-go.plan.md`](docs/plans/tamga-go.plan.md) §4. This
  is stricter than a typical review: for these files, a HIGH-severity finding blocks merge, not
  just a CRITICAL one, because a subtly wrong verifier fails silently (it accepts a forged file)
  rather than loudly.
- New table-driven tests are expected alongside any new exported behavior — this repo follows
  TDD (red/green/refactor); see `ecc:golang-testing` conventions.

## Required CI checks

Branch protection should require the following job names from
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) before merge: the `test` job across all
six matrix legs (`go-version` × `os`), plus the `golangci-lint` and `coverage` steps within it.
