#!/usr/bin/env python3
"""Benchmark exact portable/native libraries without bridge process overhead."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import platform
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path

from mlkem_native_build import ROOT, UPSTREAM_CFLAGS, command_version, load_lock, sha256


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({' '.join(command)}):\n"
            + (completed.stdout + completed.stderr).strip()
        )
    return completed


def hardware_summary() -> dict[str, str]:
    completed = run(["system_profiler", "-json", "SPHardwareDataType"])
    hardware = json.loads(completed.stdout)["SPHardwareDataType"][0]
    allowlist = {
        "modelName": "machine_name",
        "modelIdentifier": "machine_model",
        "chip": "chip_type",
        "cores": "number_processors",
        "memory": "physical_memory",
    }
    return {name: hardware[source] for name, source in allowlist.items() if source in hardware}


def verify_artifact(manifest: dict, build_dir: Path, name: str) -> Path:
    path = build_dir / name
    expected = manifest["artifacts"][name]["sha256"]
    if not path.is_file() or sha256(path) != expected:
        raise RuntimeError(f"artifact does not match manifest: {name}")
    return path


def percentile95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--portable-manifest", required=True, type=Path)
    parser.add_argument("--portable-build", required=True, type=Path)
    parser.add_argument("--native-manifest", required=True, type=Path)
    parser.add_argument("--native-build", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--batches", type=int, default=16)
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    if args.batches <= 0 or args.iterations <= 0:
        raise ValueError("batches and iterations must be positive")

    lock = load_lock()
    source = ROOT / ".deps" / "mlkem-native" / "src" / lock["archiveRoot"]
    include_root = source / "examples" / "multilevel_build_native"
    include_native = include_root / "mlkem_native"
    benchmark_source = ROOT / "backends" / "mlkem-native" / "mlkem_native_benchmark.c"
    profiles = {
        "portable": (
            load_json(args.portable_manifest),
            args.portable_build.resolve(),
        ),
        "aarch64Native": (
            load_json(args.native_manifest),
            args.native_build.resolve(),
        ),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    binaries: dict[str, Path] = {}
    profile_metadata = {}
    for name, (manifest, build_dir) in profiles.items():
        library = verify_artifact(manifest, build_dir, "libmlkem.a")
        binary = args.output_dir / f"benchmark-{name}"
        run([
            args.cc,
            *UPSTREAM_CFLAGS,
            "-I",
            str(include_root),
            "-I",
            str(include_native),
            str(benchmark_source),
            str(library),
            "-o",
            str(binary),
        ])
        binaries[name] = binary
        profile_metadata[name] = {
            "profile": manifest["profile"],
            "librarySha256": sha256(library),
            "benchmarkBinarySha256": sha256(binary),
            "nativeArithmetic": manifest["configuration"]["MLK_CONFIG_USE_NATIVE_BACKEND_ARITH"],
            "nativeFips202": manifest["configuration"]["MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202"],
        }

    samples: dict[tuple[str, int, str], list[float]] = defaultdict(list)
    checksums: dict[tuple[str, int, str], set[int]] = defaultdict(set)
    execution_order = ["portable", "aarch64Native", "aarch64Native", "portable"]
    for profile_name in execution_order:
        completed = run([
            str(binaries[profile_name]), str(args.batches), str(args.iterations)
        ])
        for row in csv.DictReader(io.StringIO(completed.stdout)):
            level = int(row["level"])
            operation = row["operation"]
            iterations = int(row["iterations"])
            total_ns = int(row["total_ns"])
            samples[(profile_name, level, operation)].append(total_ns / iterations)
            checksums[(profile_name, level, operation)].add(int(row["checksum"]))

    results = []
    for level in (512, 768, 1024):
        for operation in ("keyGen", "encapsulation", "decapsulation"):
            portable = samples[("portable", level, operation)]
            native = samples[("aarch64Native", level, operation)]
            portable_median = statistics.median(portable)
            native_median = statistics.median(native)
            results.append({
                "parameterSet": f"ML-KEM-{level}",
                "operation": operation,
                "sampleCountPerProfile": len(portable),
                "portable": {
                    "medianNsPerOperation": round(portable_median, 2),
                    "p95NsPerOperation": round(percentile95(portable), 2),
                    "minNsPerOperation": round(min(portable), 2),
                },
                "aarch64Native": {
                    "medianNsPerOperation": round(native_median, 2),
                    "p95NsPerOperation": round(percentile95(native), 2),
                    "minNsPerOperation": round(min(native), 2),
                },
                "nativeSpeedupByMedian": round(portable_median / native_median, 3),
            })

    checksum_shapes_match = all(
        len(checksums[(profile, level, operation)]) > 0
        for profile in profiles
        for level in (512, 768, 1024)
        for operation in ("keyGen", "encapsulation", "decapsulation")
    )
    checksums_match_between_profiles = all(
        checksums[("portable", level, operation)]
        == checksums[("aarch64Native", level, operation)]
        for level in (512, 768, 1024)
        for operation in ("keyGen", "encapsulation", "decapsulation")
    )
    report = {
        "schemaVersion": 1,
        "scope": "mlkem-native portable versus AArch64-native in-process benchmark",
        "environment": {
            **hardware_summary(),
            "architecture": platform.machine(),
            "os": platform.platform(),
            "compiler": command_version(args.cc),
        },
        "profiles": profile_metadata,
        "methodology": {
            "timer": "clock_gettime(CLOCK_MONOTONIC_RAW)",
            "warmupOperationsPerCase": 20,
            "batchesPerInvocation": args.batches,
            "iterationsPerBatch": args.iterations,
            "executionOrder": execution_order,
            "samplesPerProfileAndCase": args.batches * 2,
            "statistics": ["minimum", "median", "p95", "portable median / native median"],
            "processBoundary": "in-process direct public deterministic APIs",
            "excludedOverhead": "Python adapter and one-shot bridge process startup",
            "fixedDeterministicInputs": True,
        },
        "results": results,
        "integrity": {
            "benchmarkSourceSha256": hashlib.sha256(benchmark_source.read_bytes()).hexdigest(),
            "allCasesProducedChecksums": checksum_shapes_match,
            "checksumsMatchedBetweenProfiles": checksums_match_between_profiles,
        },
        "limitations": [
            "This is a local Apple M4/macOS comparison, not a Jetson or Linux ARM64 result.",
            "CPU frequency, thermal state, background load and core scheduling were not pinned.",
            "Wall-clock measurements are suitable for directional comparison, not cycle-accurate claims.",
            "Correctness is established by separate ACVP fixture differential tests, not by timing checksums."
        ],
        "passed": checksum_shapes_match and checksums_match_between_profiles
        and all(item["nativeSpeedupByMedian"] > 0 for item in results),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"cases={len(results)} samples={args.batches * 2} passed={report['passed']}")
    return 0 if report["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
