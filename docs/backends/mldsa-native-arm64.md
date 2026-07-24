# mldsa-native AArch64 build plan

## Profiles

| Profile | Role | Arithmetic backend | FIPS-202 backend |
| --- | --- | --- | --- |
| `portable-c-monolithic-multilevel` | Portable correctness baseline | portable C | portable C |
| `aarch64-native-multilevel` | ARM64 optimization profile | AArch64/NEON | selected AArch64 implementation |

The native profile is additive. It must not replace the portable build or reuse its evidence filename.

## Planned implementation

The native builder will consume the same dependency lock and use upstream's `examples/multilevel_build_native` object recipe. It will archive the three parameter-set instances into one namespaced library and link the same owner-authored adapter contract used by portable.

Before claiming an optimized build, it must:

1. require a little-endian ARM64 host or explicit cross-compilation target;
2. record compiler and host feature probes independently;
3. record whether Armv8.4-A SHA3 instructions are enabled;
4. inspect the final linked adapter binary for AArch64 arithmetic and FIPS-202 symbols;
5. run all three parameter sets through the same deterministic ACVP fixtures as portable;
6. compare portable and native responses byte-for-byte;
7. build twice and require matching artifacts;
8. write separate `mldsa-native-aarch64.json` evidence.

## CPU portability guard

The builder must not force `-march=armv8.4-a+sha3` without both compiler and target support. A binary containing SHA3 instructions cannot be treated as generic ARM64. Jetson/Linux ARM64 evidence must be recorded separately from Apple M4/macOS evidence.

## Current status

This document is a build plan only. No native artifact or performance claim is part of the current dependency/build milestone. The portable build remains the required baseline and does not depend on completion of this profile.
