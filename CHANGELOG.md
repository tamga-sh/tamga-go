# Changelog

## [1.1.0](https://github.com/tamga-sh/tamga-go/compare/tamga-go-v1.0.1...tamga-go-v1.1.0) (2026-08-13)


### Features

* SDK v2 security contract — license-file HKDF, offline format v2, HTTP 429 handling ([cf9ad3e](https://github.com/tamga-sh/tamga-go/commit/cf9ad3e670240f6dcbcab06f5b0cc63b71f1a055))

## [1.0.1](https://github.com/tamga-sh/tamga-go/compare/tamga-go-v1.0.0...tamga-go-v1.0.1) (2026-08-12)


### Bug Fixes

* enforce P-256 curve in VerifyECDSA (curve-confusion vulnerability) ([5421ba6](https://github.com/tamga-sh/tamga-go/commit/5421ba60f8ac693abc2e4b9f42ef7e1c5654338f))
* enforce P-256 curve in VerifyECDSA (curve-confusion vulnerability) ([49a1410](https://github.com/tamga-sh/tamga-go/commit/49a141020b0b2c687eed0689fd4d4cd0dfa04dfb))

## 1.0.0 (2026-08-11)


### Features

* implement client/transport, license, machine, entitlement, and error/policy sections (B/C/D/G/I/J/K) ([7f5b81f](https://github.com/tamga-sh/tamga-go/commit/7f5b81f81cb71663053c1f4093f4955aa4f5034f))
* implement license checkout crypto verification (Section E) ([ee320d4](https://github.com/tamga-sh/tamga-go/commit/ee320d4b41c330a2223557c5256cc4a4f46c10dd))
* implement machine checkout crypto verification (Section F) ([ab195e0](https://github.com/tamga-sh/tamga-go/commit/ab195e0b2ba5798686be559503c7d074e2e9a304))
* implement machine offline proof generate/verify (Section H) ([0a0d6c0](https://github.com/tamga-sh/tamga-go/commit/0a0d6c074c969025e6170e95faf0f841e2b852b0))


### Bug Fixes

* address code-review findings in path escaping, machine activation, and heartbeat scheduler ([37d8617](https://github.com/tamga-sh/tamga-go/commit/37d86176db4359a903a4ec4db4bd39d58eae71fe))
* **ci:** only run the coverage-floor gate on the ubuntu leg ([7c786ad](https://github.com/tamga-sh/tamga-go/commit/7c786ad57dd91a5a2104b9dcb6b1b24bc09e38d1))
* **ci:** upgrade golangci-lint-action to v7 for v2 config support ([f9604be](https://github.com/tamga-sh/tamga-go/commit/f9604be59ad908afc5d0c3fb5b5f82615c71caf1))
* **ci:** use external linkmode for go test on macos-latest ([1e38cf2](https://github.com/tamga-sh/tamga-go/commit/1e38cf2d5a11ca8c058c41ff9536d97dca5243ce))

## Changelog

All notable changes to this project are documented in this file, which is maintained
automatically by [release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/) on `main` — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`.github/workflows/release.yml`](.github/workflows/release.yml).

No release has been published yet.
