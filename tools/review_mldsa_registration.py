#!/usr/bin/env python3
"""Review an acvpproxy ML-DSA registration dump without exporting raw data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PARAMETER_SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    text = args.dump.read_text(encoding="utf-8")
    start = text.find("[\n")
    if start < 0:
        raise RuntimeError("registration JSON was not found in dump")
    document, _ = json.JSONDecoder().raw_decode(text[start:])
    algorithms = document[1]["algorithms"]
    modes = {algorithm["mode"]: algorithm for algorithm in algorithms}
    checks = {
        "exactlyThreeAlgorithms": len(algorithms) == 3,
        "exactModes": set(modes) == {"keyGen", "sigGen", "sigVer"},
        "allParameterSets": all(
            (algorithm.get("parameterSets") or algorithm["capabilities"][0]["parameterSets"])
            == PARAMETER_SETS
            for algorithm in algorithms
        ),
        "pureOnly": all(modes[mode].get("preHash") == ["pure"] for mode in ("sigGen", "sigVer")),
        "externalOnly": all(modes[mode].get("signatureInterfaces") == ["external"] for mode in ("sigGen", "sigVer")),
        "bothSigningVariants": modes["sigGen"].get("deterministic") == [False, True],
        "messageRange": all(
            modes[mode]["capabilities"][0]["messageLength"] == [{"min": 8, "max": 65536, "increment": 8}]
            for mode in ("sigGen", "sigVer")
        ),
        "contextRange": all(
            modes[mode]["capabilities"][0]["contextLength"] == [{"min": 0, "max": 2040, "increment": 8}]
            for mode in ("sigGen", "sigVer")
        ),
        "noHashAlgorithms": all("hashAlg" not in json.dumps(modes[mode]) for mode in ("sigGen", "sigVer")),
        "noInternalOrExternalMu": all(
            "internal" not in json.dumps(modes[mode]).lower()
            and "externalMu" not in json.dumps(modes[mode])
            for mode in ("sigGen", "sigVer")
        ),
    }
    passed = all(checks.values())
    report = {
        "schemaVersion": 1,
        "review": "acvpproxy --dump-register capability review",
        "declaredScope": "FIPS204 pure/external ML-DSA v1",
        "algorithmCount": len(algorithms),
        "modes": sorted(modes),
        "parameterSets": PARAMETER_SETS,
        "checks": checks,
        "rawRegistrationIncluded": False,
        "rawSessionIdentifiersIncluded": False,
        "networkRequired": False,
        "passed": passed,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"algorithms={len(algorithms)} checks={len(checks)} passed={passed}")
    return 0 if passed else 4


if __name__ == "__main__":
    raise SystemExit(main())
