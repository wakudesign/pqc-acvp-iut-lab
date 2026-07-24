# Common ACVP framework architecture

## Data flow

```text
ACVP request text
      |
      v
acvp_schema.py          JSON/wrapper/schema validation only
      |
      v
MLKEMVectorSet          typed groups and tests
      |
      v
mlkem_executor.py       group dispatch -> per-test execution
      |
      +----------------------> MLKEMACVPTestBackend
      |                              |
      |                         PQClean backend
      |                         future mlkem-native / leancrypto
      v
response groups + VectorSetSummary
      |
      v
serialization.py        response object -> JSON text -> file writer
```

`runner.py` orchestrates one already-downloaded vector set. It does not authenticate, register a test session, download vectors, upload responses or poll verdicts.

## Layer responsibilities

| Layer | Owns | Must not own |
| --- | --- | --- |
| Schema parser | ACVP wrapper, required metadata, typed groups/tests | Native crypto calls, output files |
| Group dispatcher | Declared mode/function routing | Field guessing, authentication |
| Per-test executor | Hex decoding, contract invocation, ACVP answer fields | Session lifecycle, backend implementation details |
| Backend contract | ML-KEM operation semantics and errors | ACVP JSON or credentials |
| PQClean backend | Subprocess invocation, native output parsing, FIPS key checks | ACVP group dispatch or response serialization |
| Serializer | Response object and stable JSON formatting | Crypto execution |
| Writer | File output after complete success | Partial-response recovery |
| Summary | Backend provenance, counts, status, structured errors | Keys, ciphertexts, seeds or credentials |

## Failure behavior

Parsing and execution errors use `StructuredError`. Error records contain only stage, stable code, fixed message, mode, tgId and tcId. They never include key material or raw command output.

The complete vector set is executed before serialization and writing. If one test fails, `serialized_response` is `None`, `testsProduced` is zero and no response file is written. This intentionally favors a clear all-or-nothing artifact over a misleading partial answer.

## Backend metadata

Every vector-set summary embeds:

- backend name and version;
- upstream commit;
- target;
- compiler;
- build flags.

`RunSummary` aggregates multiple vector-set summaries without taking ownership of ACVTS session IDs or credentials.

## PQClean baseline implementation

`PQCleanMLKEMBackend` is the first implementation of `MLKEMACVPTestBackend`. It invokes the existing deterministic one-shot binaries without a shell, validates native output sizes and implements FIPS 203 key checks.

The baseline replay produced 240/240 byte-identical responses. This preserves behavior while allowing future backends to replace only the backend adapter.

## Repository boundary

The common framework remains in this repository while its interfaces stabilize. The rationale, alternatives and objective extraction triggers are recorded in [ADR 0001](adr/0001-keep-common-framework-in-lab.md).

CI enforces that backend modules do not import network clients or reference ACVTS authentication and session-lifecycle symbols. Server communication remains an outer client-layer responsibility.
