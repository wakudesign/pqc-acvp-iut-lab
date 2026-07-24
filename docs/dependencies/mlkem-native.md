# mlkem-native dependency and portable build

## Decision

The ML-KEM backend is pinned to upstream release `v1.2.0`, commit `0ba906cb14b1c241476134d7403a811b382ca498`. The release was selected instead of the local `v1.1.0-4-g712709df` development checkout because it is the latest non-prerelease release reviewed for this integration and includes portability, correctness/constant-time hardening and proof-tooling updates.

The authoritative pin and source archive SHA-256 are in [`../../dependencies/mlkem-native.lock.json`](../../dependencies/mlkem-native.lock.json). Do not replace the commit or hash independently.

## Dependency method

This repository uses a commit-pinned source download with mandatory SHA-256 verification.

| Option | Decision | Reason |
| --- | --- | --- |
| Git submodule | Not selected | Exact provenance, but adds recursive-clone and detached-submodule friction for reviewers and CI. |
| Pinned download | Selected | One checkout, explicit commit and archive hash, no upstream history mixed into this repository. |
| Vendored source | Not selected | Best offline availability, but duplicates a security-sensitive upstream tree and obscures ownership and patch drift. |

Downloaded source lives under ignored `.deps/`; compiled objects and binaries live under ignored `build/`. Neither is presented as owner-authored source.

## Reproducible portable build

Run:

```sh
make mlkem-native-portable
```

The build tool downloads only when the verified archive is absent, safely extracts the pinned archive, builds upstream's portable monolithic multi-level example, runs its three-level smoke test, rebuilds in a second directory and requires matching library and executable hashes. It sets `ZERO_AR_DATE=1` so Apple `ar` does not place wall-clock timestamps in the static archive.

For an offline build with a previously downloaded archive:

```sh
python3 tools/mlkem_native_build.py --archive /path/to/pinned-archive.tar.gz
```

The archive is accepted only when its SHA-256 matches the lock file.

## Multi-level strategy

One portable library contains namespaced ML-KEM-512, ML-KEM-768 and ML-KEM-1024 instances. The upstream multi-level configuration includes shared code once and level-dependent code three times. Native arithmetic and native FIPS-202 feature flags are explicitly disabled for the portable baseline. The separate AArch64 profile uses upstream's `multilevel_build_native` recipe so its assembly objects, CPU requirements and artifact hashes remain distinguishable from the portable evidence. See [`../backends/mlkem-native-arm64.md`](../backends/mlkem-native-arm64.md).

The deterministic test RNG is linked only into the upstream smoke-test executable. It is not part of the library's production randomness boundary and must not be reused by the ACVP adapter except through explicitly test-only deterministic APIs.

## Security and verification scope

Upstream states that its C code has CBMC memory/type-safety coverage, while AArch64 and x86_64 assembly have HOL Light functional-correctness, memory-safety and secret-independent-timing proofs. These claims have important limits: the portable C code does not have a machine-checked end-to-end functional-correctness or constant-time proof, compiler and hardware behavior remain assumptions, and power, EM, fault and other physical side channels are outside the cited timing scope.

This project does not inherit a CAVP certificate, CMVP validation or a blanket claim that every build configuration is validated. Our evidence covers only the exact pinned source, recorded flags, target and artifacts.

Security issues must follow upstream private vulnerability reporting rather than a public issue. Upstream scope references: [README](https://github.com/pq-code-package/mlkem-native/tree/v1.2.0#formal-verification), [SOUNDNESS.md](https://github.com/pq-code-package/mlkem-native/blob/v1.2.0/SOUNDNESS.md), and [SECURITY.md](https://github.com/pq-code-package/mlkem-native/blob/v1.2.0/SECURITY.md).

## Patch and update tracking

- Local patches are currently forbidden; `localPatches` is empty in the dependency record.
- Any future patch must live under `patches/mlkem-native/`, include rationale and upstream issue/PR status, and change the build evidence.
- Review GitHub releases and private security guidance before updating.
- An update changes the release, commit and archive hash together, then reruns the portable build, upstream tests, common fixtures and later ACVTS Demo flow.
- Artifact hashes are platform/toolchain-specific evidence, not universal expected values.
