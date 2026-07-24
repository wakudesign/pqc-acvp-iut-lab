#!/usr/bin/env python3
"""Compare portable and AArch64-native ML-KEM responses on private fixtures."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from pqc_acvp.backends.mlkem_native import MLKEMNativeBackend
from pqc_acvp.runner import run_file


def payload(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    return value[1] if isinstance(value, list) else value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True, type=Path)
    parser.add_argument("--portable-bridge", required=True, type=Path)
    parser.add_argument("--portable-manifest", required=True, type=Path)
    parser.add_argument("--native-bridge", required=True, type=Path)
    parser.add_argument("--native-manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    portable = MLKEMNativeBackend.from_build_manifest(
        args.portable_bridge, args.portable_manifest
    )
    native = MLKEMNativeBackend.from_build_manifest(
        args.native_bridge, args.native_manifest
    )
    vectors = []
    with tempfile.TemporaryDirectory(prefix="mlkem-profile-compare-") as temporary:
        for request in sorted(args.session_dir.resolve().glob("*/testvector-request.json")):
            request_payload = payload(request)
            mode = request_payload.get("mode")
            if mode not in {"keyGen", "encapDecap"}:
                continue
            portable_response = Path(temporary) / f"{mode}-portable.json"
            native_response = Path(temporary) / f"{mode}-native.json"
            portable_summary = run_file(
                request, portable_response, portable, portable.metadata
            )
            native_summary = run_file(request, native_response, native, native.metadata)
            expected = request.with_name("testvector-response.json")
            portable_value = json.loads(portable_response.read_text(encoding="utf-8"))
            native_value = json.loads(native_response.read_text(encoding="utf-8"))
            expected_value = json.loads(expected.read_text(encoding="utf-8"))
            vectors.append({
                "mode": mode,
                "tests": native_summary.tests_produced,
                "portableStatus": portable_summary.status,
                "nativeStatus": native_summary.status,
                "portableEqualsNative": portable_value == native_value,
                "nativeEqualsPrivatelyRetainedPQCleanBaseline": native_value == expected_value,
            })

    passed = (
        len(vectors) == 2
        and all(
            item["portableStatus"] == "generated"
            and item["nativeStatus"] == "generated"
            and item["portableEqualsNative"]
            and item["nativeEqualsPrivatelyRetainedPQCleanBaseline"]
            for item in vectors
        )
    )
    report = {
        "schemaVersion": 1,
        "validationLevel": "offline ARM64 profile differential",
        "profiles": {
            "portable": portable.metadata.to_dict(),
            "aarch64Native": native.metadata.to_dict(),
        },
        "comparisonBaseline": "privately retained passed PQClean ACVTS Demo responses",
        "vectors": vectors,
        "totalTests": sum(item["tests"] for item in vectors),
        "rawSessionIdentifiersIncluded": False,
        "credentialsRequired": False,
        "networkRequired": False,
        "passed": passed,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"vectors={len(vectors)} tests={report['totalTests']} passed={passed}")
    return 0 if passed else 4


if __name__ == "__main__":
    raise SystemExit(main())
