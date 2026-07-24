#!/usr/bin/env python3
"""Fail-closed verification for the technical ML-DSA completion gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PARAMETER_SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
MODE_COUNTS = {"keyGen": 75, "sigGen": 90, "sigVer": 45}


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_checksums(directory: Path) -> bool:
    entries = (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    for entry in entries:
        expected, name = entry.split("  ", 1)
        path = directory / name
        if not path.is_file() or sha256(path) != expected:
            return False
    return True


def has_remote() -> bool:
    if not (ROOT / ".git").exists():
        return False
    completed = subprocess.run(
        ["git", "remote"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    return completed.returncode == 0 and bool(completed.stdout.strip())


def has_tag(tag: str) -> bool:
    if not (ROOT / ".git").exists():
        return False
    completed = subprocess.run(
        ["git", "tag", "--list", tag],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode == 0 and completed.stdout.strip() == tag


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--official-report", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    official = load(args.official_report)
    register = load(ROOT / "evidence/reviews/mldsa-native-register.json")
    validation = load(ROOT / "evidence/reviews/mldsa-native-validation.json")
    sanitized_dir = ROOT / "evidence/sanitized/mldsa-native-demo-session"
    sanitized = load(sanitized_dir / "evidence-summary.json")
    attestation = load(sanitized_dir / "export-attestation.json")
    release_record_path = ROOT / "evidence/reviews/mldsa-native-v1.1-release.json"
    release_record = load(release_record_path) if release_record_path.is_file() else {}
    vectors = {entry["mode"]: entry for entry in official.get("vectors", [])}

    same_runner = (
        official.get("passed") is True
        and official.get("selectedSurface", {}).get("tests") == 210
        and official.get("runner") == "pqc_acvp.mldsa_runner"
        and set(vectors) == set(MODE_COUNTS)
        and all(vectors[mode].get("selectedTests") == count for mode, count in MODE_COUNTS.items())
        and all(vectors[mode].get("matchesExpectedResults") is True for mode in MODE_COUNTS)
        and all(vectors[mode].get("parameterSets") == PARAMETER_SETS for mode in MODE_COUNTS)
    )
    offline_evidence = (
        register.get("passed") is True
        and validation.get("validationChecksPassed") is True
        and sanitized.get("sessionDisposition") == "passed"
        and sanitized.get("totalTests") == 210
        and sanitized.get("passedTests") == 210
        and verify_checksums(sanitized_dir)
    )
    owner_review_approved = attestation.get("humanReview") == "approved"
    release_published = (
        has_remote()
        and has_tag("v1.1")
        and release_record.get("published") is True
    )
    technical = same_runner and offline_evidence
    blockers = []
    if not (ROOT / ".git").exists():
        blockers.append("local scaffold is not initialized as a Git repository")
    elif not has_remote():
        blockers.append("Git repository has no configured remote")
    if not owner_review_approved:
        blockers.append("sanitized evidence owner review is pending")
    if not has_tag("v1.1"):
        blockers.append("v1.1 tag and GitHub release have not been created")

    report = {
        "schemaVersion": 1,
        "scope": "T03 mldsa-native completion evidence",
        "completionCriteria": {
            "sameRunnerDeclaredCoverage": {
                "runner": "pqc_acvp.mldsa_runner",
                "algorithm": "ML-DSA",
                "revision": "FIPS204",
                "parameterSets": PARAMETER_SETS,
                "modeTests": MODE_COUNTS,
                "totalTests": 210,
                "matchesOfficialExpectedResults": same_runner,
                "passed": same_runner,
            },
            "offlineEvidenceAndCiReplay": {
                "publicVectorsPinnedByHash": official.get("sourceHashesVerified") is True,
                "rawVectorsCommitted": False,
                "credentialsRequired": False,
                "workflow": ".github/workflows/credential-free-tests.yml",
                "workflowBuildsPinnedBackend": True,
                "workflowRunsUpstreamAndPortfolioReplay": True,
                "workflowRunObserved": False,
                "sanitizedChecksumsVerified": verify_checksums(sanitized_dir),
                "passed": offline_evidence,
            },
            "nistAcvtsDemo": {
                "validationLevel": "NIST ACVTS Demo",
                "parameterSets": PARAMETER_SETS,
                "modeTests": MODE_COUNTS,
                "totalTests": 210,
                "sessionDisposition": sanitized.get("sessionDisposition"),
                "rawServerIdentifiersIncluded": False,
                "passed": sanitized.get("sessionDisposition") == "passed",
            },
            "v1_1Release": {
                "gitRepositoryPresent": (ROOT / ".git").exists(),
                "remoteConfigured": has_remote(),
                "ownerEvidenceReview": attestation.get("humanReview", "missing"),
                "ownerEvidenceReviewApproved": owner_review_approved,
                "localV1_1TagPresent": has_tag("v1.1"),
                "remoteCiRunObserved": release_record.get("remoteCiRunObserved", False),
                "githubReleaseObserved": release_record.get("githubReleaseObserved", False),
                "published": release_published,
                "blockers": blockers,
            },
        },
        "claimLimitations": [
            "ACVTS Demo is not a CAVP certificate and is not CMVP module validation.",
            "HashML-DSA, internal interface and externalMu remain outside v1 scope.",
            "A configured workflow is not a remote CI run until the repository is pushed.",
            "Owner evidence approval does not mean the v1.1 tag, remote CI run or GitHub release already exists.",
        ],
        "technicalCompletionPassed": technical,
        "publicReleaseApproved": owner_review_approved,
        "releasePublished": release_published,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"technical={technical} publicReleaseApproved={owner_review_approved} "
        f"releasePublished={release_published}"
    )
    return 0 if technical else 4


if __name__ == "__main__":
    raise SystemExit(main())
