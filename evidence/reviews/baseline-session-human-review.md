# Baseline sanitized evidence — human review packet

Prepared: 2026-07-15

Status: **pending owner review**

Automated scanning passed with 0 findings. This document deliberately remains pending until the owner reads every exported file and records approval; an automated tool or AI assistant must not impersonate the human reviewer.

## Files to review

| File | SHA-256 | Review purpose |
| --- | --- | --- |
| `evidence/sanitized/baseline-session/evidence-summary.json` | `a2eaa284604d877adfc40f11ac0f365263fa2d869b8703ecb59cdf57e537ab9d` | Claims, limitations, coverage and counts |
| `evidence/sanitized/baseline-session/source-hashes.json` | `c01122b55a61062b81cb242041e548169027e802b13e5fe6b06ef47463d4de16` | Private evidence linkage without IDs or paths |
| `evidence/sanitized/baseline-session/export-attestation.json` | `873759b2f2dd88a28d2a7c46aed2036dac1ab4e7e4b0331d4073606743c565e9` | Export policy, raw-vector exclusion and pending review state |
| `evidence/sanitized/baseline-session/SHA256SUMS` | `76f4cb406e95bb1f686e857852db378c1175060ea418fae0fdc71b32fe479fc4` | Integrity of the three JSON files |

Supporting reports:

| File | SHA-256 | Result |
| --- | --- | --- |
| `evidence/reviews/baseline-session-automated-scan.json` | `830849aa2cce032018e46e85f97123421d1767a1fcc99f7a5b26002d93aeca2e` | 4 files scanned, 0 findings, passed |
| `evidence/reviews/baseline-replay.json` | `efc498defae619a972d53f2e7f71d6d0421d028c4fc5b7a9a81e0fb088ebc5d1` | Clean build, 240 tests, byte-identical, passed |

## Owner checklist

- [ ] I opened and read all four files in `evidence/sanitized/baseline-session/`.
- [ ] The wording does not imply a CAVP certificate or CMVP validation.
- [ ] The algorithm, revision, modes, parameter sets, group counts and test counts are accurate.
- [ ] No testID, vsID, personal identity, account identifier or local path is present.
- [ ] No raw vector, private key, shared credential, JWT, TOTP, Authorization header or client config is present.
- [ ] Publishing SHA-256 links to privately retained evidence is acceptable.
- [ ] `shasum -a 256 -c SHA256SUMS` succeeds from the sanitized directory.
- [ ] I approve these exact hashes for future public release.

## Approval record

Leave this section unchanged until every checkbox above is complete.

```text
decision: pending
reviewer: <owner name or GitHub handle>
reviewed_at: <UTC timestamp>
reviewed_tree_sha256: 76f4cb406e95bb1f686e857852db378c1175060ea418fae0fdc71b32fe479fc4
notes: <optional>
```

After owner approval, update `export-attestation.json` through a separate reviewed step and regenerate `SHA256SUMS`; do not edit the attestation silently.
