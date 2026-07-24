#!/usr/bin/env python3
"""Generate ACVP responses for one already-downloaded mlkem-native session."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from pqc_acvp.backends.mlkem_native import MLKEMNativeBackend
from pqc_acvp.framework import RunSummary
from pqc_acvp.runner import run_file


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True, type=Path)
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    session = args.session_dir.resolve()
    backend = MLKEMNativeBackend.from_build_manifest(args.bridge, args.manifest)
    requests = sorted(session.glob("*/testvector-request.json"))
    if not requests:
        raise RuntimeError("session has no downloaded vector sets")

    aggregate = RunSummary()
    results = []
    for request in requests:
        response = request.with_name("testvector-response.json")
        if response.exists() and not args.force:
            raise RuntimeError("response already exists; use --force to replace it")
        summary = run_file(request, response, backend, backend.metadata)
        aggregate.add(summary)
        result = {
            "algorithm": summary.algorithm,
            "mode": summary.mode,
            "revision": summary.revision,
            "status": summary.status,
            "testsSeen": summary.tests_seen,
            "testsProduced": summary.tests_produced,
            "functionCounts": dict(summary.function_counts),
            "responseSha256": sha256(response) if response.is_file() else None,
        }
        results.append(result)
        print(
            f"{summary.status}: mode={summary.mode} "
            f"seen={summary.tests_seen} produced={summary.tests_produced}"
        )

    passed = len(results) == 2 and all(item["status"] == "generated" for item in results)
    session_summary = {
        "schemaVersion": 1,
        "validationLevel": "ACVTS Demo response generation",
        "generatedAt": utc_now(),
        "backend": backend.metadata.to_dict(),
        "runSummary": aggregate.to_dict(),
        "vectors": results,
        "credentialsReadByIUT": False,
        "networkUsedByIUT": False,
        "passed": passed,
    }
    (session / "mlkem-native-iut-summary.json").write_text(
        json.dumps(session_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0 if passed else 4


if __name__ == "__main__":
    raise SystemExit(main())

