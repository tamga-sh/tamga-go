# Changelog

## [1.2.4](https://github.com/tamga-sh/tamga-go/compare/v1.2.3...v1.2.4) (2026-08-21)


### Bug Fixes

* stop claiming the rate-limit headers are never set ([5fa64bc](https://github.com/tamga-sh/tamga-go/commit/5fa64bcb2c7206bfea035efa4dd787d1b267bb3f))
* stop claiming the rate-limit headers are never set ([7783bfe](https://github.com/tamga-sh/tamga-go/commit/7783bfe13ba0ea3c4da93be1a731cf42de109432))

## [1.2.3](https://github.com/tamga-sh/tamga-go/compare/v1.2.2...v1.2.3) (2026-08-21)


### Bug Fixes

* add the auto-update check this SDK was told did not exist ([7379f55](https://github.com/tamga-sh/tamga-go/commit/7379f55af2c6d587ae1e4faf38ccf074766ae2b5))
* add the health probe, and send it with no credential ([3588552](https://github.com/tamga-sh/tamga-go/commit/358855243c9a5663e20d47e641e4689bd84916ba))
* add the missing endpoint surface (M4 code half, M10, M11, M21, M24, M26, M36) ([02bf2c7](https://github.com/tamga-sh/tamga-go/commit/02bf2c7a8656f85565232d0988b07127ca6510ee))
* add the missing process list and delete calls ([90e359a](https://github.com/tamga-sh/tamga-go/commit/90e359a3040ec270563efa52b98833f0a0ae860e))
* align the SDK with the current tamga-api server contract ([79b159c](https://github.com/tamga-sh/tamga-go/commit/79b159c70422f1d27d886e756e1eb247e4437110))
* align the SDK with the current tamga-api server contract ([31599ec](https://github.com/tamga-sh/tamga-go/commit/31599ec1d6022ddae3df3d514b3338def8a99ed3))
* correct an unauthenticated-alg comment and satisfy the linters ([4d03823](https://github.com/tamga-sh/tamga-go/commit/4d03823c16f1cd9dce7d0db0ca9ab1dd03959dac))
* correct the DEAD heartbeat-status guidance and pin the ping loop ([0105315](https://github.com/tamga-sh/tamga-go/commit/0105315e91ec43b8a4179eb9dab0781201b138f6))
* correct the heartbeat window as policy-driven, not a hardcoded 600s ([9c6c16c](https://github.com/tamga-sh/tamga-go/commit/9c6c16c4c658cde743891462db274ef65698ebee))
* cover the error and boundary paths of the new endpoint surface ([78fcf2f](https://github.com/tamga-sh/tamga-go/commit/78fcf2f4e580ff394c37f4b011cecc34716ceaa3))
* **docs:** correct four claims the new endpoints falsified ([7cbf2b3](https://github.com/tamga-sh/tamga-go/commit/7cbf2b36b203b4589fa8ab38f408c5cef0fab7ac))
* **docs:** correct the public-key encodings the API actually publishes ([d0568e0](https://github.com/tamga-sh/tamga-go/commit/d0568e00b7a97693c7373d27f5ea68656869259c))
* expose the machine read and update routes the SDK never called ([5e9474f](https://github.com/tamga-sh/tamga-go/commit/5e9474f04ab7a2da8d55c30993f0abdf6d600c33))
* floor heartbeat intervals at one second, not merely at non-positive ([aedccd4](https://github.com/tamga-sh/tamga-go/commit/aedccd4598815109822d2caec43e03b58eca7772))
* narrow the DEAD unreachability claim to the heartbeat routes ([1327846](https://github.com/tamga-sh/tamga-go/commit/1327846f77f7838c786e8020a02e025496188300))
* pin WithHTTPClient against a future timeout backfill in New ([a9cb86a](https://github.com/tamga-sh/tamga-go/commit/a9cb86a55712c567c293c80aafb2366738db7462))
* read the heartbeat window from the policy instead of assuming 600s ([1d440a4](https://github.com/tamga-sh/tamga-go/commit/1d440a4d759877e314e94dead16bb4dc53ba1411))
* state the heartbeat loop rule by status, not by DEAD ([d53a4ad](https://github.com/tamga-sh/tamga-go/commit/d53a4ad56317d9f5eb8c26a8a487c3c044e998c7))
* verify machine files against the server's v2 wire format ([da01582](https://github.com/tamga-sh/tamga-go/commit/da01582744030322464f2e78248ca0b0ba0ba6fe))
* verify machine files against the server's v2 wire format ([488a401](https://github.com/tamga-sh/tamga-go/commit/488a4012f839a628096b84026d9678f0ff72acf1))

## [1.2.2](https://github.com/tamga-sh/tamga-go/compare/v1.2.1...v1.2.2) (2026-08-18)


### Bug Fixes

* open release PRs with a GitHub App token and report the released version in the User-Agent ([#18](https://github.com/tamga-sh/tamga-go/issues/18)) ([f60dd25](https://github.com/tamga-sh/tamga-go/commit/f60dd25c0845141e8dbc9db7c7000f2d94d4b490))

## [1.2.1](https://github.com/tamga-sh/tamga-go/compare/v1.2.0...v1.2.1) (2026-08-18)


### Bug Fixes

* correct SDK documentation and align package metadata ([4f929a1](https://github.com/tamga-sh/tamga-go/commit/4f929a19cd582dbdcbc8b55a220d5a3107a465cc))

## [1.2.0](https://github.com/tamga-sh/tamga-go/compare/v1.1.0...v1.2.0) (2026-08-13)


### Features

* implement client/transport, license, machine, entitlement, and error/policy sections ([7f5b81f](https://github.com/tamga-sh/tamga-go/commit/7f5b81f81cb71663053c1f4093f4955aa4f5034f))
* implement license checkout crypto verification ([ee320d4](https://github.com/tamga-sh/tamga-go/commit/ee320d4b41c330a2223557c5256cc4a4f46c10dd))
* implement machine checkout crypto verification ([ab195e0](https://github.com/tamga-sh/tamga-go/commit/ab195e0b2ba5798686be559503c7d074e2e9a304))
* implement machine offline proof generate/verify ([0a0d6c0](https://github.com/tamga-sh/tamga-go/commit/0a0d6c074c969025e6170e95faf0f841e2b852b0))
* SDK v2 security contract — license-file HKDF, offline format v2, HTTP 429 handling ([cf9ad3e](https://github.com/tamga-sh/tamga-go/commit/cf9ad3e670240f6dcbcab06f5b0cc63b71f1a055))


### Bug Fixes

* address code-review findings in path escaping, machine activation, and heartbeat scheduler ([37d8617](https://github.com/tamga-sh/tamga-go/commit/37d86176db4359a903a4ec4db4bd39d58eae71fe))
* **ci:** only run the coverage-floor gate on the ubuntu leg ([7c786ad](https://github.com/tamga-sh/tamga-go/commit/7c786ad57dd91a5a2104b9dcb6b1b24bc09e38d1))
* **ci:** upgrade golangci-lint-action to v7 for v2 config support ([f9604be](https://github.com/tamga-sh/tamga-go/commit/f9604be59ad908afc5d0c3fb5b5f82615c71caf1))
* **ci:** use external linkmode for go test on macos-latest ([1e38cf2](https://github.com/tamga-sh/tamga-go/commit/1e38cf2d5a11ca8c058c41ff9536d97dca5243ce))
* enforce P-256 curve in VerifyECDSA (curve-confusion vulnerability) ([5421ba6](https://github.com/tamga-sh/tamga-go/commit/5421ba60f8ac693abc2e4b9f42ef7e1c5654338f))
* enforce P-256 curve in VerifyECDSA (curve-confusion vulnerability) ([49a1410](https://github.com/tamga-sh/tamga-go/commit/49a141020b0b2c687eed0689fd4d4cd0dfa04dfb))
* stop prefixing release tags with the package name ([b8c3ae0](https://github.com/tamga-sh/tamga-go/commit/b8c3ae0b799d4f7061a295867dec5137ce8b82a8))


### Miscellaneous Chores

* set explicit release version ([254d996](https://github.com/tamga-sh/tamga-go/commit/254d99623f5ed31f61fc17412d512a6403efbda6))

## [1.1.0](https://github.com/tamga-sh/tamga-go/compare/tamga-go-v1.0.1...tamga-go-v1.1.0) (2026-08-13)


### Features

* SDK v2 security contract — license-file HKDF, offline format v2, HTTP 429 handling ([cf9ad3e](https://github.com/tamga-sh/tamga-go/commit/cf9ad3e670240f6dcbcab06f5b0cc63b71f1a055))

## [1.0.1](https://github.com/tamga-sh/tamga-go/compare/tamga-go-v1.0.0...tamga-go-v1.0.1) (2026-08-12)


### Bug Fixes

* enforce P-256 curve in VerifyECDSA (curve-confusion vulnerability) ([5421ba6](https://github.com/tamga-sh/tamga-go/commit/5421ba60f8ac693abc2e4b9f42ef7e1c5654338f))
* enforce P-256 curve in VerifyECDSA (curve-confusion vulnerability) ([49a1410](https://github.com/tamga-sh/tamga-go/commit/49a141020b0b2c687eed0689fd4d4cd0dfa04dfb))

## 1.0.0 (2026-08-11)


### Features

* implement client/transport, license, machine, entitlement, and error/policy sections ([7f5b81f](https://github.com/tamga-sh/tamga-go/commit/7f5b81f81cb71663053c1f4093f4955aa4f5034f))
* implement license checkout crypto verification ([ee320d4](https://github.com/tamga-sh/tamga-go/commit/ee320d4b41c330a2223557c5256cc4a4f46c10dd))
* implement machine checkout crypto verification ([ab195e0](https://github.com/tamga-sh/tamga-go/commit/ab195e0b2ba5798686be559503c7d074e2e9a304))
* implement machine offline proof generate/verify ([0a0d6c0](https://github.com/tamga-sh/tamga-go/commit/0a0d6c074c969025e6170e95faf0f841e2b852b0))


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
