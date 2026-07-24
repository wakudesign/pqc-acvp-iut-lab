#!/usr/bin/env python3
"""Scan a sanitized evidence tree without printing matched secret values."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


PATH_PATTERNS = (
    re.compile(r"(^|/)(secure-datastore|key|keys|secrets|raw)(/|$)", re.I),
    re.compile(r"(jwt|totp|authorization|private.*key|\.p12$|\.pfx$|\.pkcs12$)", re.I),
)

CONTENT_PATTERNS = {
    "private-key": re.compile(r"BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
    "authorization": re.compile(r"Authorization\s*:\s*(?:Bearer|Basic)\s+\S+", re.I),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "macos-home": re.compile(r"/Users/[^/$<{][^\s\"']*"),
    "linux-home": re.compile(r"/home/[^/$<{][^\s\"']*"),
    "macos-temp": re.compile(r"/private/var/folders/[^\s\"']+"),
    "sensitive-assignment": re.compile(
        r"(?:password|totp(?:Seed|Secret)?|jwt|authToken|clientSecret)\s*[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        re.I,
    ),
}


def scan(root: Path) -> dict:
    findings = []
    files_scanned = 0
    bytes_scanned = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        files_scanned += 1
        data = path.read_bytes()
        bytes_scanned += len(data)
        for pattern in PATH_PATTERNS:
            if pattern.search(relative):
                findings.append({"file": relative, "rule": "denied-path"})
                break
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            findings.append({"file": relative, "rule": "non-utf8-content"})
            continue
        for name, pattern in CONTENT_PATTERNS.items():
            if pattern.search(text):
                findings.append({"file": relative, "rule": name})
    return {
        "schemaVersion": 1,
        "scanner": "tools/check_public_tree.py",
        "rootLabel": root.name,
        "filesScanned": files_scanned,
        "bytesScanned": bytes_scanned,
        "findings": findings,
        "passed": not findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = scan(args.root.resolve())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"scanned={report['filesScanned']} findings={len(report['findings'])} passed={report['passed']}")
    return 0 if report["passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
