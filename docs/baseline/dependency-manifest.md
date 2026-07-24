# Baseline dependency manifest

Inventory date: 2026-07-15

## Cryptographic implementation

| Dependency | Provenance | Baseline pin | Purpose |
| --- | --- | --- | --- |
| PQClean | `https://github.com/PQClean/PQClean.git` | `3730b32aa50ba9e712592c1476bdd048f5f6ed7e` | ML-KEM-512/768/1024 clean implementations and FIPS 202 primitives |

Required PQClean paths:

- `crypto_kem/ml-kem-512/clean/`
- `crypto_kem/ml-kem-768/clean/`
- `crypto_kem/ml-kem-1024/clean/`
- `common/fips202.c` and headers

PQClean implementation licenses are Public Domain / CC0. Original per-implementation licenses and the FIPS 202 attribution header must be retained.

## Baseline adapter and build

| Component | Baseline |
| --- | --- |
| C compiler | Apple clang 21.0.0, target `arm64-apple-darwin25.5.0` |
| C flags | `-O2 -std=c11 -Wall -Wextra -Wpedantic` plus PQClean include paths |
| Make | GNU Make 3.81 |
| Python | 3.14.5; exporter/scanner/replay use standard library only |
| Host | macOS 26.5 / Darwin 25.5.0 / ARM64 |

The current baseline is an Apple Silicon execution environment. It is not Jetson/Linux evidence.

## ACVP transport provenance

| Dependency | Pin | Role |
| --- | --- | --- |
| acvpproxy | `a4b6eabf3801f6245ef540d1771b9742f835ff01` | Registration, vector download, answer upload and verdict retrieval for the historical Demo session |

acvpproxy is not needed for offline replay. Credentials, config and `secure-datastore` are explicitly outside the replay dependency set.

## Tooling outside the public dependency set

- NIST ACVP Server checkout `b121fee031dc65d32c96f4109a42a10dacbe2076` was used for local research but is not needed by the exact offline replay.
- GenVal tooling API `c0f53f2f3931c2514c142a5df32cfa6763edf276` is owner-written and currently `UNLICENSED`; the entire local-server environment is intentionally excluded from the public repositories.
- Node, npm, Rust and Tauri are not baseline ML-KEM replay dependencies.

## Provenance limitation

The accepted responses are reproducible, but historical encap/decap binary hashes differ from the clean rebuild. The project therefore claims response reproducibility, not deterministic historical binary reproduction.
