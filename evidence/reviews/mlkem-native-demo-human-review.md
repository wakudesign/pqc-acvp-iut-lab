# mlkem-native Demo sanitized evidence — human review packet

Prepared: 2026-07-15

Status: **pending owner review**

The NIST ACVTS Demo vector sets passed and the automated public-tree scan found zero findings. This packet remains pending because an automated tool or AI assistant must not approve the owner's release decision.

## Files to review

| File | SHA-256 | Review purpose |
| --- | --- | --- |
| `evidence/sanitized/mlkem-native-demo-session/evidence-summary.json` | `c5a08297697ad5e622e4510fee508807c4fb54171e1897149dfa9ed18ccb4536` | Demo claim, limitations, backend metadata and aggregate coverage |
| `evidence/sanitized/mlkem-native-demo-session/source-hashes.json` | `81cee696f0533e3a84b763a41d3614da8747463f2c13eeac8e345f8d75db6186` | Private evidence linkage without IDs, paths or vectors |
| `evidence/sanitized/mlkem-native-demo-session/export-attestation.json` | `4e826eb79557ff3ea72bd23e6f116c83fa8b73022360d044c813685bb61ce2ef` | Export policy, raw-vector exclusion and pending review state |
| `evidence/sanitized/mlkem-native-demo-session/SHA256SUMS` | `815f6f7e2028da943eaba527ebf9348f624dfcb84180c0587f31a3bc174cdd9d` | Integrity of the three JSON files |

Supporting automated scan: `evidence/reviews/mlkem-native-demo-automated-scan.json` (`8d0334e1bd20369a31d1a803fb015c13a54a1080f1fc161ef218dd14582e136e`), 4 files scanned, 0 findings, passed.

## Owner checklist

- [ ] I opened and read all four files in `evidence/sanitized/mlkem-native-demo-session/`.
- [ ] The wording says NIST ACVTS Demo and does not imply a CAVP certificate or CMVP validation.
- [ ] ML-KEM FIPS 203, both modes, all three parameter sets, 15 groups and 240 tests are accurate.
- [ ] No test-session ID, vector-set ID, account identity, personal identity or local path is present.
- [ ] No raw vector, private key, shared credential, JWT, TOTP, Authorization header or client config is present.
- [ ] Publishing the listed SHA-256 links to privately retained evidence is acceptable.
- [ ] `shasum -a 256 -c SHA256SUMS` succeeds from the sanitized directory.
- [ ] I approve these exact hashes for future public release.

## Approval record

Leave this section unchanged until every checkbox above is complete.

```text
decision: pending
reviewer: <owner name or GitHub handle>
reviewed_at: <UTC timestamp>
reviewed_tree_sha256: 815f6f7e2028da943eaba527ebf9348f624dfcb84180c0587f31a3bc174cdd9d
notes: <optional>
```

After owner approval, update `export-attestation.json` through a separate reviewed step and regenerate `SHA256SUMS`; do not edit the attestation silently.
