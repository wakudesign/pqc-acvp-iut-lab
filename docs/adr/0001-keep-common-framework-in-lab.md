# ADR 0001: Keep the common framework in `pqc-acvp-iut-lab`

- Status: Accepted
- Date: 2026-07-15

## Context

The portfolio needs one ACVP parser, dispatcher, response serializer and typed backend contract for PQClean, mlkem-native, mldsa-native and leancrypto adapters. A separate `acvp-iut-core` repository could make that framework independently reusable, but today there is only one concrete repository consuming it and its interfaces are still evolving as additional backends are added.

The framework must remain independent from ACVTS credentials, authentication and test-session lifecycle even while it stays in this repository.

## Decision

Keep the framework as the `pqc_acvp` Python package inside `pqc-acvp-iut-lab` for v1. Preserve extraction-ready boundaries:

- backend-neutral schema, execution, serialization and summary modules;
- backend adapters under `pqc_acvp/backends/`;
- no network client or ACVTS session lifecycle in backend modules;
- credential-free fixtures and unit tests in CI;
- backend metadata passed into the framework rather than discovered from client state.

## Alternatives considered

### Create `acvp-iut-core` now

This gives the cleanest repository boundary, but introduces a second version, release process, dependency pin and cross-repository CI matrix before a second independent consumer exists. Early interface changes would require coordinated releases and make portfolio reproduction harder.

### Copy framework code into every implementation repository

This avoids a shared dependency but creates parser and error-semantics drift. Security fixes and ACVP schema updates would need to be repeated and compared across repositories.

### Keep modular code in the lab repository

This has the lowest coordination cost while the contracts stabilize. The risk is accidental coupling to lab paths or session tooling, so CI enforces backend boundaries and all runners consume already-downloaded documents.

## Consequences

- One checkout is enough to reproduce framework tests and compare backends.
- Internal interfaces can evolve without coordinated package releases during the portfolio phase.
- The package is not yet independently versioned for third-party consumers.
- A future extraction will require history and packaging work, but module boundaries limit the mechanical changes.

## Extraction triggers

Reconsider a separate `acvp-iut-core` repository when any two of these are true:

1. A second repository imports the framework as a dependency rather than invoking the lab tooling.
2. Framework and backend adapters need independent release cadences.
3. A non-Python consumer requires a stable cross-language protocol or C ABI.
4. Access control or licensing requires the framework and backend sources to be published separately.
5. Cross-repository CI is already required for two or more maintained consumers.

