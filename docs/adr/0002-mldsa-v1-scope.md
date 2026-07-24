# ADR 0002: ML-DSA v1 ACVP scope

- Status: Accepted
- Date: 2026-07-15

## Context

The portfolio needs an ML-DSA implementation that demonstrates more than deterministic key generation while remaining small enough to review, reproduce and validate as one release increment. The selected backend, mldsa-native, exposes all three FIPS 204 parameter sets and supports key generation, signing and verification. Its API can later support pure ML-DSA, HashML-DSA, deterministic signing, hedged signing and external `mu` workflows.

The existing `PQClean/iut_mldsa` prototype is a useful behavioral baseline, but it only implements key generation. Its runner, command-line secret transport and process-global `randombytes` shim are not suitable abstractions for the new adapter.

## Known facts

- The existing PQClean prompt contains 75 key-generation tests: 25 each for ML-DSA-44, ML-DSA-65 and ML-DSA-87.
- The existing binary accepts `parameterSet` and a 32-byte seed as command-line arguments, then prints `pk` and `sk` as hex.
- The PQClean RNG shim returns the supplied seed for the first randomness request and derives later bytes with SHAKE256. It is coupled to PQClean's `randombytes` entry point.
- mldsa-native has explicit internal APIs for deterministic key generation and signing randomness, so the adapter does not need a process-global RNG override.
- The reviewed ACVP sample set exercises keyGen, sigGen and sigVer across all three parameter sets. Pure external sigGen covers deterministic and non-deterministic groups and supplies `rnd` for the latter.
- ACVP lengths are registered in bits. FIPS 204 context strings are at most 255 bytes.

## Unknowns and assumptions

- The dependency release or commit is deliberately not selected by this ADR; T03 dependency work will pin and record it separately.
- The proposed registration ranges must still be verified with the repository's registration dump and the current ACVTS Demo service.
- The v1 adapter assumes the validation-only hedged path receives the ACVP-provided 32-byte `rnd`. A production signing API must obtain fresh randomness internally and must not accept caller-controlled `rnd` by default.
- Raw ACVTS sessions, identifiers and credentials remain private. Only sanitized summaries and public sample-vector metadata may enter this repository.

## Alternatives considered

### Key generation only

This would reuse most of the PQClean baseline, but would not demonstrate the signing contract, context handling, randomness boundary or invalid-signature semantics. It does not meet the portfolio objective.

### Deterministic signing only

This is simpler, but avoids the most important API distinction between deterministic and hedged signing. It would leave the ACVP-supplied `rnd` mapping untested.

### Full mldsa-native ACVP surface in v1

This would include HashML-DSA, all allowed pre-hash functions, the internal interface and external `mu`. It provides the broadest coverage, but introduces several independent abstractions and internal-interface assurance cases before the basic adapter is established.

### Pure external ML-DSA with both signing variants

This covers key generation, signing, verification, three security levels, context strings and both randomness modes without adding hash dispatch or internal `mu` semantics. It is the smallest scope that demonstrates the complete external ML-DSA lifecycle.

## Decision

The v1 ML-DSA adapter will support:

| Dimension | v1 decision |
| --- | --- |
| Revision | FIPS204 |
| Parameter sets | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| Modes | keyGen, sigGen, sigVer |
| Interface | external only |
| Signature type | pure ML-DSA only |
| sigGen randomness | deterministic and non-deterministic/hedged |
| Message length | 1 to 8192 bytes; registration `8..65536` bits in steps of 8 |
| Context length | 0 to 255 bytes; registration `0..2040` bits in steps of 8 |
| Verification result | boolean `testPassed` |

The corresponding registration intent is:

- `keyGen`: all three parameter sets;
- `sigGen`: all three parameter sets, `interface = external`, `preHash = pure`, and both values of `deterministic`;
- `sigVer`: all three parameter sets, `interface = external`, and `preHash = pure`;
- no `externalMu` declaration because the internal interface is not registered;
- no `hashAlg` declaration because pre-hash signing is not registered.

For validation, non-deterministic/hedged sigGen maps the vector's 32-byte `rnd` directly to mldsa-native's signing-randomness input. Deterministic sigGen uses the backend's deterministic operation and must not silently draw system randomness. Context is treated as an opaque byte string, including the empty string.

An invalid signature is a successful backend execution whose response is `testPassed: false`. Malformed input, an unsupported capability or backend failure is an execution error and must not be serialized as an ordinary invalid signature.

## Explicitly deferred

- HashML-DSA / pre-hash signing and verification;
- hash-algorithm capability dispatch;
- internal-interface signing and verification;
- `externalMu = true` and `externalMu = false` registrations;
- internal deterministic rejection-path assurance cases;
- a production signing API or production entropy policy;
- optimized AArch64 builds, dependency pinning and release selection.

## Risks and guards

- **Registration drift:** ACVP drafts and Demo behavior may change. Generate and review `--dump-register` output before any session; do not silently narrow ranges to make registration pass.
- **Validation API misuse:** Caller-supplied `rnd` is necessary for ACVP replay but unsafe as a production default. Keep the IUT interface explicitly validation-only.
- **Secret disclosure:** Do not pass seeds, secret keys, messages or randomness on command lines or include them in errors and evidence.
- **Scope creep:** Supporting APIs upstream does not make them registered capabilities. Reject pre-hash and internal groups until a later ADR accepts them.
- **False verification failures:** Preserve the distinction between a cryptographic negative result and adapter/backend failure in tests and summaries.

## Consequences and exit criteria

The first implementation can use one ML-DSA-specific adapter contract for all three parameter sets. It must execute the selected keyGen, sigGen and sigVer groups through the common runner, cover deterministic and hedged signing, and test empty and maximum-length contexts. Registration output must match this ADR before ACVTS Demo execution.

Expanding the registration to pre-hash or internal interfaces requires a new decision record, contract additions and dedicated negative and assurance tests.
