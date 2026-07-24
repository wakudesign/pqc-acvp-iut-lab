# mlkem-native on ARM64

## Decision

The ARM64 work keeps two independent build profiles from the same pinned mlkem-native v1.2.0 source:

| Profile | Purpose | Native arithmetic | Native FIPS-202 |
| --- | --- | --- | --- |
| `portable-c-multilevel` | Portable correctness baseline | disabled | disabled |
| `aarch64-native-multilevel` | ARM64 optimized implementation | enabled | enabled |

Replacing the portable profile was rejected because it would remove the control needed to attribute correctness and performance changes. Forcing `-march=armv8.4-a+sha3` was also rejected: the build follows upstream host/compiler detection and records the effective compiler predefines and final linked symbols instead.

## Build

Run the profiles independently:

```sh
make mlkem-native-portable
make mlkem-native-arm64
```

The AArch64 build uses upstream's `examples/multilevel_build_native` recipe and archives the three parameter-set object groups into one library. The owner-authored bridge links that library without the upstream test RNG. Both profiles are built twice and require identical artifact hashes.

The recorded Apple M4 build has these effective requirements:

- little-endian AArch64;
- Advanced SIMD / NEON;
- Armv8.4-A SHA3 instructions.

Apple Clang defines `__ARM_FEATURE_SHA3` by default on this M4. The legacy macOS sysctl key used by upstream's auxiliary probe did not report the feature, so the manifest records both observations. `nm` inspection of the final bridge—not merely the static archive—confirms that AArch64 NTT and SHA3 assembly symbols were linked. The binary also completed the three-level deterministic smoke test.

See [`../../evidence/build/mlkem-native-aarch64.json`](../../evidence/build/mlkem-native-aarch64.json).

## Correctness comparison

The native profile runs the same contract and negative tests as portable. The complete suite has 48 passing tests, including six backend integration tests for each profile.

`tools/compare_mlkem_native_profiles.py` replays the privately retained two-mode ML-KEM fixture set through both profiles. Across 240 tests:

- portable output equals AArch64-native output;
- AArch64-native output equals the retained PQClean baseline response;
- no raw session identifiers, raw vectors or credentials are exported in the report.

See [`../../evidence/reviews/mlkem-native-arm64-differential.json`](../../evidence/reviews/mlkem-native-arm64-differential.json).

## Benchmark methodology

Run:

```sh
make mlkem-native-arm64-benchmark
```

The benchmark calls the public deterministic C APIs in-process. It deliberately excludes Python adapter and one-shot bridge process-startup overhead, which would measure IPC rather than ML-KEM. It covers key generation, encapsulation and decapsulation for ML-KEM-512, 768 and 1024.

The recorded run uses:

- `clock_gettime(CLOCK_MONOTONIC_RAW)`;
- 20 warm-up operations per case;
- two invocations per profile, 16 batches per invocation and 500 operations per batch;
- balanced execution order: portable, native, native, portable;
- minimum, median and p95 wall-clock nanoseconds per operation;
- speedup defined as portable median divided by native median.

On this Apple M4/macOS run, native median speedups range from approximately 1.76x to 2.08x across the nine cases. The exact values are evidence for this machine and run, not a universal ARM64 claim.

See [`../../evidence/benchmarks/mlkem-native-arm64.json`](../../evidence/benchmarks/mlkem-native-arm64.json).

## Limits

- This is an Apple M4/macOS ARM64 result, not a Jetson or Linux ARM64 result.
- CPU frequency, thermal state, background load and core scheduling were not pinned.
- Wall-clock results support a directional comparison, not cycle-accurate claims.
- Correctness comes from fixture differential tests; benchmark checksums are only an anti-optimization integrity check.
- A binary built with SHA3 instructions must not be moved to an ARM64 CPU that lacks those instructions. A portable or separately dispatched build is required for heterogeneous deployment.
