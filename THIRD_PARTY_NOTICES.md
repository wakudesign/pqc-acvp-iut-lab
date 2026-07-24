# Third-party notices

## mlkem-native

- Project: `pq-code-package/mlkem-native`
- Upstream: <https://github.com/pq-code-package/mlkem-native>
- Pinned release: `v1.2.0`
- Pinned commit: `0ba906cb14b1c241476134d7403a811b382ca498`
- Dependency method: verified pinned download; upstream source is not committed to this repository
- Core source license expression: `Apache-2.0 OR ISC OR MIT`
- License selected for the core source used by this project: `Apache-2.0`

The portable multi-level smoke-test binary also links upstream's test-only `notrandombytes` implementation. Its SPDX expression is `LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT`. It is never used by a production API or shipped as a cryptographic RNG.

The upstream archive retains the complete `LICENSE`, copyright headers, documentation licensing and attribution. This repository's adapter and build tooling are separate work and must not be represented as the upstream cryptographic implementation.

## mldsa-native

- Project: `pq-code-package/mldsa-native`
- Upstream: <https://github.com/pq-code-package/mldsa-native>
- Pinned release: `v1.0.0-beta2` (prerelease)
- Pinned commit: `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`
- Dependency method: verified pinned download; upstream source is not committed to this repository
- Core source license expression: `Apache-2.0 OR ISC OR MIT`
- License selected for the core source used by this project: `Apache-2.0`

The portable smoke-test binary links upstream's test-only `notrandombytes` implementation. Its license terms are retained in the upstream archive. It is not linked into `libmldsa.a` and must never be represented as production entropy.

The upstream archive retains the complete `LICENSE`, copyright headers, documentation licensing and attribution. This repository's adapter and build tooling are separate work and must not be represented as the upstream cryptographic implementation.
