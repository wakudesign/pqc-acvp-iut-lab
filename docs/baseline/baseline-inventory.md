# ML-KEM baseline inventory

Inventory date: 2026-07-15

## Claim boundary

This baseline demonstrates that a PQClean-backed ML-KEM IUT produced responses accepted by the NIST ACVTS Demo server and that the responses can be reproduced offline. It is not a CAVP certificate, a CMVP module validation, or a claim that every later source revision has passed ACVTS.

## Coverage

| Mode / function | Test type | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | Total |
| --- | --- | ---: | ---: | ---: | ---: |
| keyGen | AFT | 25 | 25 | 25 | 75 |
| encapsulation | AFT | 25 | 25 | 25 | 75 |
| decapsulation | VAL | 10 | 10 | 10 | 30 |
| encapsulationKeyCheck | VAL | 10 | 10 | 10 | 30 |
| decapsulationKeyCheck | VAL | 10 | 10 | 10 | 30 |
| **Total** | | **80** | **80** | **80** | **240** |

The two vector sets and all 240 individual tests received a passed disposition.

## Execution boundary

- keyGen, encapsulation and decapsulation execute in C one-shot binaries linked to PQClean clean ML-KEM implementations.
- encapsulationKeyCheck is implemented in the Python adapter as a length and canonical-coefficient check.
- decapsulationKeyCheck is implemented in the Python adapter as a length, embedded-public-key and `SHA3-256(ek) == H(ek)` consistency check.

The key-check adapter logic must not be presented as a PQClean library API.

## Evidence tiers

- `evidence/sanitized/baseline-session/`: summary, coverage and hashes only. It contains no test-session IDs, vector-set IDs, raw vectors, credentials or local paths.
- Internal exact evidence: locally retained ACVTS Demo request, response and verdict files. These are not copied into this repository.
- Public synthetic fixture: planned separately so external reviewers can exercise the adapter without redistributing user-specific Demo vector sets.

## Reproduction result

An isolated clean build regenerated all 240 responses byte-for-byte. The replay used no NIST credentials, no `secure-datastore` and no network connection. See `evidence/reviews/baseline-replay.json` after running the internal replay command.
