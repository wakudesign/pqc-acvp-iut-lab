#!/usr/bin/env python3
"""Clean-build and exactly replay a locally retained ML-KEM baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


MODE_ALIASES = {"keyGen": "mlkem-keygen", "encapDecap": "mlkem-encap-decap"}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def run(command: list[str], cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True)


def replay(pqclean: Path, session: Path) -> dict:
    iut = pqclean / "iut_mlkem"
    summary = load_json(session / "iut-session-summary.json")
    results = []
    with tempfile.TemporaryDirectory(prefix="pqc-baseline-replay-") as temporary:
        temp = Path(temporary)
        bins = temp / "bin"
        run(["make", "BIN_DIR=" + str(bins), "clean"], cwd=iut)
        run(["make", "BIN_DIR=" + str(bins)], cwd=iut)

        for entry in summary.get("results", []):
            mode = entry["mode"]
            if mode not in MODE_ALIASES:
                continue
            vector_dir = session / str(entry["vsId"])
            request = vector_dir / "testvector-request.json"
            expected = vector_dir / "testvector-response.json"
            actual = temp / f"{MODE_ALIASES[mode]}-response.json"
            if mode == "keyGen":
                command = [
                    sys.executable,
                    str(iut / "scripts/keygen_prompt_to_answer.py"),
                    str(request),
                    str(bins / "mlkem_keygen_once"),
                    str(actual),
                ]
            else:
                command = [
                    sys.executable,
                    str(iut / "scripts/encapdecap_prompt_to_answer.py"),
                    str(request),
                    str(bins / "mlkem_encap_once"),
                    str(bins / "mlkem_decap_once"),
                    str(actual),
                    "auto",
                ]
            run(command)
            identical = actual.read_bytes() == expected.read_bytes()
            results.append({
                "alias": MODE_ALIASES[mode],
                "mode": mode,
                "tests": entry["testsSeen"],
                "byteIdentical": identical,
                "responseSha256": sha256_file(actual),
            })

        binaries = {
            name: sha256_file(bins / name)
            for name in ("mlkem_keygen_once", "mlkem_encap_once", "mlkem_decap_once")
        }

    passed = len(results) == 2 and all(result["byteIdentical"] for result in results)
    return {
        "schemaVersion": 1,
        "replay": "internal-exact-baseline",
        "networkRequired": False,
        "credentialsRequired": False,
        "secureDatastoreRequired": False,
        "cleanBuild": True,
        "vectors": results,
        "cleanBuildBinarySha256": binaries,
        "totalTests": sum(result["tests"] for result in results),
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pqclean-dir", required=True, type=Path)
    parser.add_argument("--session-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = replay(args.pqclean_dir.resolve(), args.session_dir.resolve())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"tests={report['totalTests']} passed={report['passed']}")
    return 0 if report["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
