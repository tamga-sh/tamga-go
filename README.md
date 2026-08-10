# tamga-go

Official Go SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Go applications.

> **Status: scaffold.** This repository currently contains infrastructure only — module
> layout, CI/release automation, and stub files with doc comments describing intended
> contents. No HTTP or cryptographic logic is implemented yet. See
> [`docs/plans/tamga-go.plan.md`](docs/plans/tamga-go.plan.md) for the full implementation
> task breakdown and build order.

## Install

```bash
go get github.com/tamga-sh/tamga-go
```

Package: `github.com/tamga-sh/tamga-go` · Registry: [pkg.go.dev](https://pkg.go.dev/github.com/tamga-sh/tamga-go)
· Supported Go versions: 1.22, 1.23.

## Quickstart

The snippet below shows the intended shape of the simplest call — validating a license by key —
against the stub API surface scaffolded in this repository. **It is illustrative only and will
not compile or run yet**: `tamga.New` and `Client.ValidateByKey` are not implemented (see
[`license.go`](license.go), [`client.go`](client.go)).

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/tamga-sh/tamga-go"
)

func main() {
	client, err := tamga.New("your-account-id")
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

## Security notice

This SDK's offline verification code (license/machine checkout files, offline proofs) has to
reproduce the Tamga server's exact signature and encryption conventions byte-for-byte —
including two easy-to-get-backwards details:

- The Ed25519 checkout signature covers the **base64 string bytes** of the encrypted payload,
  not its decoded bytes.
- The `.lic` file's encryption key is the license key's raw UTF-8 bytes, zero-padded/truncated
  to 32 bytes — **not** a KDF (the `.machine` file's key, by contrast, *is* a proper
  HKDF-SHA256 derivation).

Read [`checkout_license.go`](checkout_license.go), [`checkout_machine.go`](checkout_machine.go),
and [`proof.go`](proof.go)'s doc comments before relying on or modifying any verification code
here — these sections carry a mandatory security review gate for exactly this reason.

## Documentation

- [`docs/plans/tamga-go.plan.md`](docs/plans/tamga-go.plan.md) — implementation plan, task
  checklist, and architecture for this repository.
- [`tamga-api`'s `docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md) —
  the authoritative protocol/feature reference this SDK implements against, including the
  server-side gaps that are deliberately out of scope for this SDK's v1.

## License

MIT — see [LICENSE](LICENSE).
