#!/usr/bin/env python3
"""Replay private local fixtures through mlkem-native and export summary-only evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from pqc_acvp.backends.mlkem_native import MLKEMNativeBackend
from pqc_acvp.framework import RunSummary
from pqc_acvp.runner import run_file


ALIASES = {"keyGen": "mlkem-keygen", "encapDecap": "mlkem-encap-decap"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def payload(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    return document[1] if isinstance(document, list) else document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True, type=Path)
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    backend = MLKEMNativeBackend.from_build_manifest(args.bridge, args.manifest)
    requests = sorted(args.session_dir.resolve().glob("*/testvector-request.json"))
    run_summary = RunSummary()
    vectors = []
    with tempfile.TemporaryDirectory(prefix="mlkem-native-replay-") as temporary:
        for request in requests:
            mode = payload(request)["mode"]
            if mode not in ALIASES:
                continue
            actual = Path(temporary) / f"{ALIASES[mode]}.json"
            summary = run_file(request, actual, backend, backend.metadata)
            run_summary.add(summary)
            expected = request.with_name("testvector-response.json")
            semantic_identical = (
                actual.is_file()
                and expected.is_file()
                and json.loads(actual.read_text(encoding="utf-8"))
                == json.loads(expected.read_text(encoding="utf-8"))
            )
            vectors.append({
                "alias": ALIASES[mode],
                "mode": mode,
                "testsSeen": summary.tests_seen,
                "testsProduced": summary.tests_produced,
                "status": summary.status,
                "semanticIdenticalToPQClean": semantic_identical,
                "byteIdenticalToPQClean": (
                    actual.is_file() and expected.is_file()
                    and actual.read_bytes() == expected.read_bytes()
                ),
                "responseSha256": sha256(actual) if actual.is_file() else None,
                "functionCounts": dict(summary.function_counts),
            })

    passed = (
        len(vectors) == 2
        and all(
            item["status"] == "generated"
            and item["semanticIdenticalToPQClean"]
            and item["byteIdenticalToPQClean"]
            for item in vectors
        )
    )
    report = {
        "schemaVersion": 1,
        "validationLevel": "offline differential fixture replay",
        "backend": backend.metadata.to_dict(),
        "comparisonBaseline": "PQClean responses from a privately retained passed ACVTS Demo session",
        "networkRequired": False,
        "credentialsRequired": False,
        "rawSessionIdentifiersIncluded": False,
        "runSummary": run_summary.to_dict(),
        "vectors": vectors,
        "totalTests": sum(item["testsProduced"] for item in vectors),
        "passed": passed,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"vectors={len(vectors)} tests={report['totalTests']} passed={passed}")
    return 0 if passed else 4


if __name__ == "__main__":
    raise SystemExit(main())

