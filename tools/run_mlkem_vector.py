#!/usr/bin/env python3
"""Run one local ML-KEM ACVP request through the common framework."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pqc_acvp.backends import PQCleanMLKEMBackend
from pqc_acvp.framework import BackendMetadata
from pqc_acvp.runner import run_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--pqclean-bin-dir", required=True, type=Path)
    args = parser.parse_args()
    metadata = BackendMetadata(
        name="PQClean", version="baseline", commit="3730b32aa50ba9e712592c1476bdd048f5f6ed7e",
        target="arm64-apple-darwin25.5.0", compiler="Apple clang 21.0.0",
        flags=("-O2", "-std=c11", "-Wall", "-Wextra", "-Wpedantic"),
    )
    backend = PQCleanMLKEMBackend(args.pqclean_bin_dir, metadata)
    summary = run_file(args.request, args.response, backend, metadata)
    args.summary.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if summary.status == "generated" else 4


if __name__ == "__main__":
    raise SystemExit(main())
