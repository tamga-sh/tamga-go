# Security Policy

## Scope

`tamga-go` is a client SDK: it makes HTTP calls to a Tamga API server and, more sensitively,
implements from-scratch offline cryptographic verification of license/machine checkout files and
offline proofs. The highest-risk code in this repository lives in:

- [`checkout_license.go`](checkout_license.go) — `.lic` file parsing and Ed25519/AES-256-GCM
  verification.
- [`checkout_machine.go`](checkout_machine.go) — `.machine` file parsing and multi-scheme
  (Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256) verification.
- [`proof.go`](proof.go) — offline proof generation/verification (RSA-2048 PKCS#1 v1.5, byte-exact
  JSON serialization).
- [`internal/crypto/`](internal/crypto) — the underlying primitive wrappers all three of the above
  build on.

Every file in this list carries a mandatory `security-reviewer` gate before any change merges —
see [`docs/plans/tamga-go.plan.md`](docs/plans/tamga-go.plan.md) §4 and
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Supported Versions

This SDK is pre-1.0; the latest published minor version receives security fixes. Once a 1.x
series exists, the two most recent minor versions will receive security patches.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a suspected security vulnerability.**

Report it privately via GitHub's [private vulnerability reporting](https://github.com/tamga-sh/tamga-go/security/advisories/new)
feature on this repository. Include:

- The affected file(s)/function(s) and, if possible, a minimal reproduction.
- Whether the issue is a verification bypass (a forged `.lic`/`.machine` file or offline proof
  that this SDK would incorrectly accept as valid), an information leak, a denial-of-service via
  malformed/adversarial input, or something else.
- The version (git commit or tagged release) you tested against.

You should receive an initial response within 5 business days. Confirmed vulnerabilities will be
fixed in a private branch and disclosed via a GitHub Security Advisory alongside the patched
release; we will credit reporters who wish to be credited.

## What Counts as a Vulnerability Here

Given this SDK's actual attack surface (an offline file/proof verifier, not a server), the
highest-severity class of bug is **a verifier that accepts something it should reject** — for
example:

- `(*LicenseFile).Verify` / `(*MachineFile).Verify` accepting a signature computed over the wrong
  bytes (see the base64-string-vs-decoded-bytes gotcha documented throughout `checkout_*.go`).
- `(*MachineFile).Verify` dispatching to the wrong algorithm for a given `LicenseScheme`, or
  failing to reject `RSA_2048_JWT_RS256`.
- `VerifyOfflineProof` accepting a signature computed over a differently-serialized (but
  semantically equivalent) JSON payload.
- Any timing side-channel in signature/tag comparison that could help an attacker forge a valid
  file/proof without the private key.

A verifier that is *too strict* (rejects a genuinely valid, server-issued file) is a correctness
bug, not primarily a security one, but is still worth reporting if you believe it has security
implications (e.g. it could be leveraged for a denial-of-service against license activation).

## Known, Deliberate Non-Vulnerabilities

The following are intentional design decisions, not bugs, and reports about them will be closed
without action (though corrections/clarifications to this list are welcome):

- The `.lic` file's encryption key derivation (`internal/crypto/naivekey.go`) is a zero-pad/
  truncate transform, not a real KDF. This is mandated by server wire compatibility — see that
  file's doc comment.
- Auth is not currently enforced server-side on the license/machine validate/check-in endpoints
  (a server-side gap, not a client-side one) — this SDK still always sends its configured
  credentials for forward-compatibility.
- No client-side rate-limit/backoff handling — the server does not send `429` today.
