#!/usr/bin/env python3
"""Export summary-only ACVP evidence through a fail-closed policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


VERSION = "0.1.0"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def payload(data: Any) -> dict[str, Any]:
    if isinstance(data, list) and len(data) >= 2 and isinstance(data[1], dict):
        return data[1]
    if isinstance(data, dict):
        return data
    raise ValueError("unsupported ACVP JSON wrapper")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_count(vector: dict[str, Any]) -> int:
    return sum(len(group.get("tests", [])) for group in vector.get("testGroups", []))


def verdict_is_passed(verdict: dict[str, Any], expected_tests: int) -> bool:
    tests = verdict.get("tests", [])
    return (
        verdict.get("disposition") == "passed"
        and len(tests) == expected_tests
        and all(test.get("result") == "passed" for test in tests)
    )


def require_empty_output(path: Path) -> None:
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise ValueError(f"output must be a new empty directory: {path}")
    else:
        path.mkdir(parents=True)


def load_iut_summary(source: Path) -> dict[str, Any]:
    candidates = (
        source / "mldsa-native-iut-summary.json",
        source / "mlkem-native-iut-summary.json",
        source / "iut-session-summary.json",
    )
    for candidate in candidates:
        if candidate.is_file():
            summary = load_json(candidate)
            if not isinstance(summary, dict):
                raise ValueError("IUT summary must be a JSON object")
            return summary
    raise ValueError("session has no supported IUT summary")


def summary_results(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = summary.get("results")
    if entries is None:
        entries = summary.get("runSummary", {}).get("vectorSets")
    if not isinstance(entries, list):
        raise ValueError("IUT summary has no vector results")
    return {entry["mode"]: entry for entry in entries}


def vector_directories_by_mode(source: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for request_path in sorted(source.glob("*/testvector-request.json")):
        request = payload(load_json(request_path))
        mode = request.get("mode")
        if not isinstance(mode, str) or mode in result:
            raise ValueError("vector modes must be present and unique")
        result[mode] = request_path.parent
    return result


def export(source: Path, policy_path: Path, output: Path) -> None:
    policy = load_json(policy_path)
    if policy.get("schemaVersion") != 1:
        raise ValueError("unsupported policy schemaVersion")
    if policy.get("includeRawVectors") is not False:
        raise ValueError("this exporter only supports includeRawVectors=false")

    require_empty_output(output)
    expected = policy["expected"]
    session_summary = load_iut_summary(source)
    session_verdict = payload(load_json(source / "verdict.json"))
    if session_verdict.get("passed") is not True:
        raise ValueError("session verdict is not passed")

    results_by_mode = summary_results(session_summary)
    directories_by_mode = vector_directories_by_mode(source)
    vectors: list[dict[str, Any]] = []
    source_hashes: dict[str, Any] = {"sessionAlias": policy["sessionAlias"], "vectors": []}

    for vector_policy in expected["vectors"]:
        mode = vector_policy["mode"]
        run = results_by_mode.get(mode)
        if not run or run.get("status") != "generated":
            raise ValueError(f"missing generated result for mode {mode}")

        vector_dir = directories_by_mode.get(mode)
        if vector_dir is None:
            raise ValueError(f"missing downloaded vector for mode {mode}")
        request_path = vector_dir / "testvector-request.json"
        response_path = vector_dir / "testvector-response.json"
        verdict_path = vector_dir / "verdict.json"
        request = payload(load_json(request_path))
        response = payload(load_json(response_path))
        verdict = payload(load_json(verdict_path))

        groups = request.get("testGroups", [])
        functions = sorted({
            group.get("function") or (
                mode if request.get("algorithm") == "ML-DSA" else "keyGen"
            )
            for group in groups
        })
        parameter_sets = sorted({group["parameterSet"] for group in groups})
        tests = test_count(request)

        if request.get("algorithm") != expected["algorithm"]:
            raise ValueError(f"algorithm mismatch for {mode}")
        if request.get("revision") != expected["revision"]:
            raise ValueError(f"revision mismatch for {mode}")
        if parameter_sets != sorted(expected["parameterSets"]):
            raise ValueError(f"parameter set mismatch for {mode}")
        if len(groups) != vector_policy["groups"] or tests != vector_policy["tests"]:
            raise ValueError(f"group/test count mismatch for {mode}")
        if functions != sorted(vector_policy["functions"]):
            raise ValueError(f"function mismatch for {mode}")
        if test_count(response) != tests:
            raise ValueError(f"response test count mismatch for {mode}")
        if not verdict_is_passed(verdict, tests):
            raise ValueError(f"vector verdict is not fully passed for {mode}")

        vectors.append({
            "alias": vector_policy["alias"],
            "mode": mode,
            "groups": len(groups),
            "tests": tests,
            "functions": functions,
            "parameterSets": parameter_sets,
            "disposition": "passed",
            "passedTests": tests,
        })
        source_hashes["vectors"].append({
            "alias": vector_policy["alias"],
            "requestSha256": sha256_file(request_path),
            "responseSha256": sha256_file(response_path),
            "verdictSha256": sha256_file(verdict_path),
        })

    evidence_summary = {
        "schemaVersion": 1,
        "sessionAlias": policy["sessionAlias"],
        "serverEnvironment": "NIST ACVTS Demo",
        "claim": "ACVTS Demo responses passed and are reproducible offline",
        "claimLimitations": [
            "Not a CAVP certificate",
            "Not a CMVP module validation",
            "Raw vectors and server identifiers are not included"
        ],
        "algorithm": expected["algorithm"],
        "revision": expected["revision"],
        "vectors": vectors,
        "totalTests": sum(item["tests"] for item in vectors),
        "passedTests": sum(item["passedTests"] for item in vectors),
        "sessionDisposition": "passed",
    }
    if "backend" in session_summary:
        backend = session_summary["backend"]
        evidence_summary["backend"] = {
            key: backend[key]
            for key in ("name", "version", "commit", "compiler", "target", "flags")
            if key in backend
        }

    write_json(output / "evidence-summary.json", evidence_summary)
    write_json(output / "source-hashes.json", source_hashes)
    attestation = {
        "schemaVersion": 1,
        "exporter": "tools/export_evidence.py",
        "exporterVersion": VERSION,
        "policySha256": sha256_file(policy_path),
        "sourceHashesSha256": canonical_sha256(source_hashes),
        "rawVectorsIncluded": False,
        "credentialsRequired": False,
        "humanReview": "pending",
    }
    write_json(output / "export-attestation.json", attestation)

    manifest_entries = []
    for name in ("evidence-summary.json", "source-hashes.json", "export-attestation.json"):
        manifest_entries.append(f"{sha256_file(output / name)}  {name}")
    (output / "SHA256SUMS").write_text("\n".join(manifest_entries) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    export(args.source.resolve(), args.policy.resolve(), args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
