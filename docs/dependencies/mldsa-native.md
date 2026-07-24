# mldsa-native dependency and portable build

## Decision

The ML-DSA backend is pinned to upstream release `v1.0.0-beta2`, commit `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`. This is the newest reviewed upstream release that exposes the ML-DSA operations selected by ADR 0002, but it is explicitly a prerelease. The prerelease status is a maintenance risk, not a validation failure: every update requires a fresh source review, build replay and ACVP validation.

The authoritative pin, archive URL and SHA-256 are in [`../../dependencies/mldsa-native.lock.json`](../../dependencies/mldsa-native.lock.json). Release, commit and archive hash must change together.

## Dependency method

This repository uses a commit-pinned source download with mandatory SHA-256 verification.

| Option | Decision | Reason |
| --- | --- | --- |
| Git submodule | Not selected | Preserves upstream history but adds recursive-clone and detached-submodule friction. |
| Pinned download | Selected | Gives reviewers one checkout and makes the exact source archive independently verifiable. |
| Vendored source | Not selected | Improves offline availability but duplicates a security-sensitive tree and blurs source ownership. |

Verified source is extracted under ignored `.deps/`; objects, libraries and executables are written under ignored `build/`. No upstream source or compiled artifact is committed as owner-authored work.

## Reproducible portable build

Run:

```sh
make mldsa-native-portable
```

For an offline build with the pinned archive already available:

```sh
python3 tools/mldsa_native_build.py --archive /path/to/pinned-archive.tar.gz
```

The build uses upstream's `examples/monolithic_build_multilevel` recipe. That recipe creates one portable C library containing namespaced ML-DSA-44, ML-DSA-65 and ML-DSA-87 instances. It does not compile native assembly. The smoke executable links upstream's test-only deterministic RNG and performs key generation, signing and verification for all three parameter sets; the RNG is not part of `libmldsa.a`.

The tool builds in two different output directories and requires identical artifact hashes. `ZERO_AR_DATE=1` removes archive timestamps on Apple toolchains. The evidence records source identity, compiler, flags, target, recipe hash, artifact hashes, smoke result and native-symbol scan.

## AArch64 profile

The portable profile is the correctness and portability baseline even on an Apple M4. A later independent `aarch64-native-multilevel` profile will use upstream's `examples/multilevel_build_native` recipe and host/compiler feature detection. It must record linked AArch64 arithmetic and FIPS-202 symbols, required CPU features and separate artifact hashes. It must never replace or silently alter the portable profile.

See [`../backends/mldsa-native-arm64.md`](../backends/mldsa-native-arm64.md).

## License and security notes

The core source is offered under `Apache-2.0 OR ISC OR MIT`; this project selects Apache-2.0 while preserving the complete upstream license archive and notices. The smoke binary also contains upstream test-only `notrandombytes`; it is never used as production entropy or linked into the library.

Upstream reports CBMC checks for C memory/type safety and tests against timing leakage, plus HOL Light proofs for a subset of native functions. These are scoped claims: they do not prove the complete portable build functionally correct, do not eliminate compiler and hardware assumptions, and do not cover power, EM, fault-injection or speculative-execution attacks. This build does not inherit a CAVP certificate or CMVP validation.

Security issues must use upstream private vulnerability reporting rather than a public issue. Review [`SECURITY.md`](https://github.com/pq-code-package/mldsa-native/blob/v1.0.0-beta2/SECURITY.md) and [`SOUNDNESS.md`](https://github.com/pq-code-package/mldsa-native/blob/v1.0.0-beta2/SOUNDNESS.md) before updating.

## Patch and update policy

- Local patches are currently forbidden; `localPatches` is empty.
- A future patch must live under `patches/mldsa-native/`, explain its security impact and record upstream status.
- Updating a prerelease requires reviewing whether a stable release now exists.
- Every update reruns portable reproducibility, upstream tests, adapter fixtures and ACVTS Demo validation.
- Artifact hashes are specific to the recorded platform and toolchain, not universal expected values.
