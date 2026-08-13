# tamga-go

[![CI](https://github.com/tamga-sh/tamga-go/actions/workflows/ci.yml/badge.svg)](https://github.com/tamga-sh/tamga-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/tamga-sh/tamga-go.svg)](https://pkg.go.dev/github.com/tamga-sh/tamga-go)
[![coverage](https://codecov.io/gh/tamga-sh/tamga-go/branch/main/graph/badge.svg)](https://codecov.io/gh/tamga-sh/tamga-go)

Official Go SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Go applications.

## Install

```bash
go get github.com/tamga-sh/tamga-go
```

Package: `github.com/tamga-sh/tamga-go` · Docs: [pkg.go.dev/github.com/tamga-sh/tamga-go](https://pkg.go.dev/github.com/tamga-sh/tamga-go)
· Supported Go versions: 1.22, 1.23.

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

See [`examples/`](examples/) for full runnable programs covering validation, check-in, offline
license/machine file verification, the machine lifecycle (activate, heartbeat, offline proof),
and entitlement checks.

## Auth transports

`tamga.New` requires exactly one auth transport, set via an `Option`. `WithLicenseKey` is the
primary transport for embedded/client SDKs and this package's own default path; use `WithAuth`
for any of the other four (mirrors `docs/sdk.md` §1's server try-order: Bearer → Basic → License
→ Cookie → query param):

| Transport | Wire form | Option |
|---|---|---|
| License key | `Authorization: License <key>` | `WithLicenseKey(key)` (shorthand) or `WithAuth(tamga.LicenseKeyAuth{Key: key})` |
| Bearer token | `Authorization: Bearer <token>` | `WithAuth(tamga.BearerAuth{Token: token})` |
| Basic — email/password | `Authorization: Basic base64(email:password)` | `WithAuth(tamga.NewBasicAuthEmailPassword(email, password))` |
| Basic — token | `Authorization: Basic base64(token:)` (empty password) | `WithAuth(tamga.NewBasicAuthToken(token))` |
| Basic — license key | `Authorization: Basic base64(license:<key>)` | `WithAuth(tamga.NewBasicAuthLicenseKey(key))` |
| Session cookie | `Cookie: Tamga-Session=<uuid>` | `WithAuth(tamga.SessionCookieAuth{SessionID: id})` — browser/portal only, not relevant to most Go consumers |
| Query parameter | `?token=<token>` | `WithAuth(tamga.QueryParamAuth{Token: token})` |

## Security notice

This SDK's offline verification code (license/machine checkout files, offline proofs) has to
reproduce the Tamga server's exact signature and encryption conventions byte-for-byte —
including several easy-to-get-backwards details. **Read this before relying on or modifying any
verification code:**

- The Ed25519 checkout signature (`.lic`/`.machine` files) covers the **base64 string bytes** of
  the encrypted payload, not its decoded bytes. Getting this backwards silently accepts forged
  files while passing a self-generated test fixture that repeats the same mistake — see
  [`checkout_license.go`](checkout_license.go)'s `Verify` doc comment.
- The `.lic` file's encryption key is the license key's raw UTF-8 bytes, zero-padded/truncated to
  32 bytes — **not** a KDF (`internal/crypto/naivekey.go`). The `.machine` file's key, by
  contrast, *is* a proper HKDF-SHA256 derivation (`internal/crypto/hkdf.go`) requiring both the
  license key and the machine's fingerprint.
- Machine checkout's signing scheme is driven by the **license's own `scheme` field**, never
  guessed from the file's `alg` string — `RSA_2048_PKCS1_SIGN` and `RSA_2048_JWT_RS256` share an
  alg suffix server-side and cannot be safely disambiguated from file content alone.
  `RSA_2048_JWT_RS256` itself is rejected outright for machine files.
- The offline-proof payload's JSON serialization must match the server's field order
  byte-for-byte (alphabetical at every nesting level, not source-code order) — see
  [`proof.go`](proof.go)'s doc comments for how this SDK reproduces that.

`checkout_license.go`, `checkout_machine.go`, `proof.go`, and everything under
`internal/crypto/` carry a mandatory security-reviewer gate before merge for exactly this reason
— see [`SECURITY.md`](SECURITY.md).

## Documentation

- [pkg.go.dev/github.com/tamga-sh/tamga-go](https://pkg.go.dev/github.com/tamga-sh/tamga-go) —
  generated API reference.
- [`tamga-api`'s `docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md) —
  the authoritative protocol/feature reference this SDK implements against, including the
  server-side gaps that are deliberately out of scope for this SDK's v1.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup and PR expectations.
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting process.

## License

MIT — see [LICENSE](LICENSE).
