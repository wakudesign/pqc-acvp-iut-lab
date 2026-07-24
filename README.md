# pqc-acvp-iut-lab

Portfolio repository for ACVP IUT integrations.

Status: private local scaffold. No implementation or evidence is approved for public release yet.

## Scope and ownership

This repository demonstrates my integration work around the ACVP protocol:

- the backend-neutral ML-KEM contract and layered request/response framework in `src/pqc_acvp/`;
- the mlkem-native Python adapter and owner-authored one-shot C bridge;
- the ML-DSA-specific framework, mldsa-native adapter and owner-authored validation bridge;
- reproducible portable and AArch64-native build tooling;
- capability registration definitions, negative tests, differential replay, evidence export and benchmark methodology.

The ML-KEM cryptographic implementation is **not** my work. It comes from upstream [`pq-code-package/mlkem-native`](https://github.com/pq-code-package/mlkem-native), pinned to v1.2.0 at the commit recorded in `dependencies/mlkem-native.lock.json`. Upstream source is downloaded into ignored `.deps/` storage and is not vendored or presented as owner-authored code. See `THIRD_PARTY_NOTICES.md` and `docs/dependencies/mlkem-native.md`.

The ML-DSA cryptographic implementation is also upstream work. It comes from [`pq-code-package/mldsa-native`](https://github.com/pq-code-package/mldsa-native), pinned to v1.0.0-beta2 at the commit recorded in `dependencies/mldsa-native.lock.json`. This repository owns the ACVP contract, parsing, dispatch, bridge, build integration, tests and evidence pipeline—not the cryptographic core.

The local ACVTS client, credentials, session lifecycle and raw vectors are outside this repository. The IUT adapter consumes already-downloaded vectors and never reads ACVTS credentials or manages network sessions.

## Validation claims

- The portable mlkem-native profile produced passing responses for one NIST ACVTS Demo session covering ML-KEM keyGen and encapDecap, all three parameter sets and 240 tests.
- The AArch64-native profile passed offline differential testing against the portable profile and a privately retained PQClean baseline; it has not been claimed as a separate NIST ACVTS Demo session.
- The portable mldsa-native profile produced passing NIST ACVTS Demo responses for FIPS 204 keyGen, pure/external sigGen and pure/external sigVer: all three parameter sets and 210 tests.
- The ML-DSA v1 declaration does not include HashML-DSA, the internal interface or external `mu` workflows.
- ACVTS Demo evidence is not a CAVP certificate and is not CMVP module validation.
- Sanitized evidence excludes raw vectors, server identifiers and credentials. The mldsa-native Demo evidence received owner approval on 2026-07-24; other repository release gates are tracked separately.

Current baseline tooling is intentionally split into:

- sanitized, summary-only evidence suitable for public review after approval;
- an internal exact replay that consumes locally held ACVTS Demo requests without credentials or network access.

See `docs/baseline/` and `tools/`.

Run the credential-free contract tests with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The common framework architecture is documented in `docs/architecture.md`.

Build the pinned portable mldsa-native backend and replay both the upstream public sample surface and this repository's declared 210-test surface with:

```sh
make mldsa-native-official-replay
```

Verify the committed summary-only completion evidence without credentials or raw vectors with:

```sh
make mldsa-native-completion
```

On an ARM64 host, build and compare the pinned portable and AArch64-native mlkem-native profiles with:

```sh
make mlkem-native-portable
make mlkem-native-arm64
make mlkem-native-arm64-benchmark
```

The recorded Apple M4 results and their limits are documented in `docs/backends/mlkem-native-arm64.md`. They must not be represented as Jetson or generic Linux ARM64 performance.
