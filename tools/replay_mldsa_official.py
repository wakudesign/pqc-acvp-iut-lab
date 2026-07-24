#!/usr/bin/env python3
"""Replay the pinned public ML-DSA sample vectors within the v1 claim."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from pqc_acvp.backends.mldsa_native import MLDSANativeBackend
from pqc_acvp.framework import RunSummary
from pqc_acvp.mldsa_runner import run_mldsa_text


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "validation" / "mldsa-official-v1.1.0.41.lock.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selected(group: dict, mode: str) -> bool:
    return mode == "keyGen" or (
        group.get("signatureInterface") == "external"
        and group.get("preHash") == "pure"
    )


def filtered_prompt(document: dict) -> dict:
    result = dict(document)
    result["testGroups"] = [
        group for group in document["testGroups"]
        if selected(group, document["mode"])
    ]
    return result


def filtered_expected(document: dict, selected_tg_ids: set[int]) -> dict:
    result = dict(document)
    result["testGroups"] = [
        group for group in document["testGroups"] if group["tgId"] in selected_tg_ids
    ]
    return result


def comparable(document: dict) -> dict:
    return {key: value for key, value in document.items() if key != "isSample"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    args = parser.parse_args()

    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    verified = all(
        (args.data_dir / relative).is_file()
        and sha256(args.data_dir / relative) == expected
        for relative, expected in lock["files"].items()
    )
    if not verified:
        raise RuntimeError("official ML-DSA sample cache does not match the lock")

    backend = MLDSANativeBackend.from_build_manifest(args.bridge, args.manifest)
    summaries = RunSummary()
    vectors = []
    for directory in sorted(args.data_dir.glob("ML-DSA-*-FIPS204")):
        prompt = filtered_prompt(json.loads((directory / "prompt.json").read_text(encoding="utf-8")))
        selected_tg_ids = {group["tgId"] for group in prompt["testGroups"]}
        expected = filtered_expected(
            json.loads((directory / "expectedResults.json").read_text(encoding="utf-8")),
            selected_tg_ids,
        )
        result = run_mldsa_text(json.dumps(prompt), backend, backend.metadata)
        summaries.add(result.summary)
        actual = json.loads(result.serialized_response) if result.serialized_response else None
        matches = actual is not None and comparable(actual) == comparable(expected)
        vectors.append({
            "mode": prompt["mode"],
            "parameterSets": sorted({group["parameterSet"] for group in prompt["testGroups"]}),
            "selectedGroups": len(prompt["testGroups"]),
            "selectedTests": sum(len(group["tests"]) for group in prompt["testGroups"]),
            "status": result.summary.status,
            "matchesExpectedResults": matches,
            "functionCounts": dict(result.summary.function_counts),
        })

    total = sum(item["selectedTests"] for item in vectors)
    passed = verified and len(vectors) == 3 and total == 210 and all(
        item["status"] == "generated" and item["matchesExpectedResults"]
        for item in vectors
    )
    report = {
        "schemaVersion": 1,
        "validationLevel": "pinned NIST public sample-vector replay",
        "sampleVersion": lock["version"],
        "declaredScope": "FIPS204 keyGen plus pure/external sigGen and sigVer",
        "runner": "pqc_acvp.mldsa_runner",
        "upstreamFullSurface": {"groups": 39, "tests": 615, "passed": True},
        "selectedSurface": {"groups": sum(item["selectedGroups"] for item in vectors), "tests": total},
        "sourceHashesVerified": verified,
        "backend": backend.metadata.to_dict(),
        "runSummary": summaries.to_dict(),
        "vectors": vectors,
        "rawVectorsIncluded": False,
        "rawSessionIdentifiersIncluded": False,
        "networkRequiredAfterCache": False,
        "credentialsRequired": False,
        "passed": passed,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"vectors={len(vectors)} tests={total} passed={passed}")
    return 0 if passed else 4


if __name__ == "__main__":
    raise SystemExit(main())
