#!/usr/bin/env python3
"""Replay the internal two-vector-set baseline through the common framework."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from pqc_acvp.backends import PQCleanMLKEMBackend
from pqc_acvp.framework import BackendMetadata, RunSummary
from pqc_acvp.runner import run_file


ALIASES = {"keyGen": "mlkem-keygen", "encapDecap": "mlkem-encap-decap"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True, type=Path)
    parser.add_argument("--pqclean-bin-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    session = args.session_dir.resolve()
    internal = json.loads((session / "iut-session-summary.json").read_text(encoding="utf-8"))
    metadata = BackendMetadata(
        "PQClean", "baseline", "3730b32aa50ba9e712592c1476bdd048f5f6ed7e",
        "arm64-apple-darwin25.5.0", "Apple clang 21.0.0",
        ("-O2", "-std=c11", "-Wall", "-Wextra", "-Wpedantic"),
    )
    backend = PQCleanMLKEMBackend(args.pqclean_bin_dir, metadata)
    vectors = []
    run_summary = RunSummary()
    with tempfile.TemporaryDirectory(prefix="common-framework-replay-") as temporary:
        for entry in internal["results"]:
            mode = entry["mode"]
            vector_dir = session / str(entry["vsId"])
            actual = Path(temporary) / f"{ALIASES[mode]}.json"
            summary = run_file(vector_dir / "testvector-request.json", actual, backend, metadata)
            run_summary.add(summary)
            expected = vector_dir / "testvector-response.json"
            vectors.append({
                "alias": ALIASES[mode],
                "mode": mode,
                "testsSeen": summary.tests_seen,
                "testsProduced": summary.tests_produced,
                "status": summary.status,
                "byteIdentical": actual.is_file() and actual.read_bytes() == expected.read_bytes(),
                "responseSha256": sha256(actual) if actual.is_file() else None,
                "functionCounts": dict(summary.function_counts),
            })
    passed = len(vectors) == 2 and all(v["status"] == "generated" and v["byteIdentical"] for v in vectors)
    report = {
        "schemaVersion": 1,
        "framework": "pqc_acvp common ML-KEM framework",
        "backend": metadata.to_dict(),
        "networkRequired": False,
        "credentialsRequired": False,
        "sessionLifecycleManaged": False,
        "runSummary": run_summary.to_dict(),
        "vectors": vectors,
        "totalTests": sum(v["testsProduced"] for v in vectors),
        "passed": passed,
    }
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"tests={report['totalTests']} passed={passed}")
    return 0 if passed else 4


if __name__ == "__main__":
    raise SystemExit(main())
