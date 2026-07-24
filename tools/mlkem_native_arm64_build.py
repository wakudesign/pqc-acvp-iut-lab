#!/usr/bin/env python3
"""Build and inventory the pinned mlkem-native AArch64 native profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from mlkem_native_build import (
    ROOT,
    UPSTREAM_CFLAGS,
    acquire_archive,
    command_version,
    extract_source,
    load_lock,
    sha256,
)


DEFAULT_CACHE = ROOT / ".deps" / "mlkem-native"
DEFAULT_BUILD = ROOT / "build" / "mlkem-native" / "aarch64-native-multilevel"
DEFAULT_MANIFEST = ROOT / "evidence" / "build" / "mlkem-native-aarch64.json"


def run(command: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
    if completed.returncode != 0:
        details = (completed.stdout + completed.stderr).strip()
        raise RuntimeError(f"command failed ({' '.join(command)}):\n{details}")
    return completed


def probe_sha3(cc: str) -> dict[str, bool | str]:
    host = subprocess.run(
        ["sysctl", "-n", "hw.optional.armv8_2_sha3"],
        capture_output=True,
        text=True,
        check=False,
    )
    host_supported = host.returncode == 0 and host.stdout.strip() == "1"
    predefined = subprocess.run(
        [cc, "-dM", "-E", "-x", "c", "-"],
        input="",
        capture_output=True,
        text=True,
        check=False,
    )
    compiler_defines_sha3 = (
        predefined.returncode == 0 and "__ARM_FEATURE_SHA3" in predefined.stdout
    )
    with tempfile.TemporaryDirectory(prefix="mlkem-sha3-probe-") as temporary:
        output = Path(temporary) / "probe.o"
        compiler = subprocess.run(
            [
                cc,
                "-march=armv8.4-a+sha3",
                "-x",
                "c",
                "-c",
                "-o",
                str(output),
                "-",
            ],
            input=(
                "int main(void) { __asm__(\"eor3 v0.16b, v1.16b, v2.16b, "
                "v3.16b\" ::: \"v0\", \"v1\", \"v2\", \"v3\"); return 0; }\n"
            ),
            capture_output=True,
            text=True,
            check=False,
        )
    compiler_supported = compiler.returncode == 0
    enabled = compiler_defines_sha3 or (compiler_supported and host_supported)
    return {
        "compilerSupportsArmv84Sha3": compiler_supported,
        "compilerDefinesArmFeatureSha3ByDefault": compiler_defines_sha3,
        "hostReportedArmv82Sha3": host_supported,
        "hostProbeKey": "hw.optional.armv8_2_sha3",
        "sha3InstructionsEnabled": enabled,
        "sha3EnablementSource": (
            "compiler predefined __ARM_FEATURE_SHA3"
            if compiler_defines_sha3
            else "explicit -march after compiler and host probes"
            if enabled
            else "not enabled"
        ),
    }


def parse_bridge_output(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            raise RuntimeError("unexpected bridge smoke-test output")
        name, value = line.split("=", 1)
        result[name] = value
    return result


def bridge_smoke(bridge: Path) -> None:
    for level in (512, 768, 1024):
        keygen = subprocess.run(
            [str(bridge), "keygen", str(level)],
            input=("00" * 32 + "\n" + "11" * 32 + "\n"),
            capture_output=True,
            text=True,
            check=True,
        )
        pair = parse_bridge_output(keygen.stdout)
        encaps = subprocess.run(
            [str(bridge), "encaps", str(level)],
            input=(pair["ek"] + "\n" + "22" * 32 + "\n"),
            capture_output=True,
            text=True,
            check=True,
        )
        encapsulated = parse_bridge_output(encaps.stdout)
        decaps = subprocess.run(
            [str(bridge), "decaps", str(level)],
            input=(pair["dk"] + "\n" + encapsulated["c"] + "\n"),
            capture_output=True,
            text=True,
            check=True,
        )
        if parse_bridge_output(decaps.stdout).get("k") != encapsulated.get("k"):
            raise RuntimeError(f"native bridge round trip failed for ML-KEM-{level}")


def build_once(
    source: Path,
    output: Path,
    cc: str,
    ar: str,
    feature_probe: dict[str, bool | str],
) -> tuple[dict[str, dict[str, int | str]], dict[str, bool | str | list[str]]]:
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)
    native_example = source / "examples" / "multilevel_build_native"
    native_include = native_example / "mlkem_native"
    environment = os.environ.copy()
    environment["ZERO_AR_DATE"] = "1"
    library = output / "libmlkem.a"
    bridge = output / "mlkem_native_bridge"
    bridge_source = ROOT / "backends" / "mlkem-native" / "mlkem_native_bridge.c"

    logs = []
    relative_output = os.path.relpath(output / "objects", native_example)
    make_command = [
        "make", "-C", str(native_example), f"BUILD_DIR={relative_output}",
        f"CC={cc}", "AUTO=1", "mlkem_objs",
    ]
    completed = run(make_command, env=environment)
    logs.append("$ " + " ".join(make_command) + "\n" + completed.stdout + completed.stderr)
    objects = sorted((output / "objects").rglob("*.o"))
    if not objects:
        raise RuntimeError("upstream native build produced no objects")
    commands = [
        [ar, "rcs", str(library), *map(str, objects)],
        ["strip", "-S", str(library)],
        [
            cc, *UPSTREAM_CFLAGS, "-I", str(native_example), "-I",
            str(native_include), str(bridge_source), str(library), "-o", str(bridge),
        ],
    ]
    for command in commands:
        completed = run(command, env=environment)
        logs.append("$ " + " ".join(command) + "\n" + completed.stdout + completed.stderr)

    run([str(bridge), "--self-test-zeroize"])
    bridge_smoke(bridge)
    symbols = run(["nm", str(bridge)]).stdout
    symbol_checks: dict[str, bool | str | list[str]] = {
        "aarch64ArithmeticAssemblyPresent": "ntt_aarch64_asm" in symbols,
        "aarch64Fips202AssemblyPresent": "keccak_f1600_x1_" in symbols,
        "arithmeticBackend": "AArch64/NEON assembly",
        "fips202Backend": (
            "AArch64 SHA3-instruction assembly"
            if feature_probe["sha3InstructionsEnabled"]
            else "AArch64 scalar/NEON assembly without SHA3 instructions"
        ),
        "requiredCpuFeatures": [
            "AArch64 little-endian",
            "Advanced SIMD (NEON)",
            *(
                ["Armv8.4-A SHA3 instructions"]
                if feature_probe["sha3InstructionsEnabled"]
                else []
            ),
        ],
        "optionalCpuFeatures": (
            []
            if feature_probe["sha3InstructionsEnabled"]
            else ["Armv8.4-A SHA3 instructions"]
        ),
    }
    if not symbol_checks["aarch64ArithmeticAssemblyPresent"]:
        raise RuntimeError("AArch64 arithmetic assembly was not linked")
    if not symbol_checks["aarch64Fips202AssemblyPresent"]:
        raise RuntimeError("AArch64 FIPS-202 assembly was not linked")

    artifacts = {
        "libmlkem.a": {"sha256": sha256(library), "size": library.stat().st_size},
        "mlkem_native_bridge": {"sha256": sha256(bridge), "size": bridge.stat().st_size},
    }
    (output / "build.log").write_text("\n".join(logs), encoding="utf-8")
    return artifacts, symbol_checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--ar", default=os.environ.get("AR", "ar"))
    args = parser.parse_args()

    if platform.machine().lower() not in {"arm64", "aarch64"} or sys.byteorder != "little":
        raise RuntimeError("this profile requires a little-endian ARM64 host")

    lock = load_lock()
    archive = acquire_archive(lock, args.cache_dir.resolve(), args.archive)
    source = extract_source(lock, archive, args.cache_dir.resolve())
    feature_probe = probe_sha3(args.cc)
    build_dir = args.build_dir.resolve()
    first, backend = build_once(source, build_dir, args.cc, args.ar, feature_probe)
    repeat_dir = build_dir.parent / f"{build_dir.name}-repeat"
    second, repeat_backend = build_once(source, repeat_dir, args.cc, args.ar, feature_probe)
    repeat_match = first == second and backend == repeat_backend
    shutil.rmtree(repeat_dir, ignore_errors=True)

    target = run([args.cc, "-dumpmachine"]).stdout.strip()
    manifest = {
        "schemaVersion": 1,
        "dependency": {
            key: lock[key]
            for key in (
                "name", "release", "commit", "archiveSha256", "dependencyMethod",
                "localPatches", "sourceLicenseExpression", "selectedSourceLicense",
            )
        },
        "profile": "aarch64-native-multilevel",
        "parameterSets": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "configuration": {
            "MLK_CONFIG_MULTILEVEL_BUILD": True,
            "MLK_CONFIG_USE_NATIVE_BACKEND_ARITH": True,
            "MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202": True,
            "MLK_FORCE_AARCH64": True,
            "ZERO_AR_DATE": "1",
        },
        "featureDetection": feature_probe,
        "nativeBackend": backend,
        "toolchain": {
            "target": target,
            "compiler": args.cc,
            "compilerVersion": command_version(args.cc),
            "archiver": args.ar,
            "archiverVersion": command_version(args.ar),
            "compilerFlags": [
                *UPSTREAM_CFLAGS,
                "-DMLK_FORCE_AARCH64",
                *(
                    ["-march=armv8.4-a+sha3"]
                    if feature_probe["sha3InstructionsEnabled"]
                    and not feature_probe["compilerDefinesArmFeatureSha3ByDefault"]
                    else []
                ),
            ],
        },
        "upstreamBuildRecipeSha256": sha256(
            source / "examples" / "multilevel_build_native" / "Makefile"
        ),
        "bridgeSourceSha256": sha256(
            ROOT / "backends" / "mlkem-native" / "mlkem_native_bridge.c"
        ),
        "artifacts": first,
        "smokeTestPassed": True,
        "bridgeZeroizeSelfTestPassed": True,
        "repeatBuildMatched": repeat_match,
        "credentialsRequired": False,
        "networkRequiredAfterFetch": False,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"release={lock['release']} target={target} native=enabled "
        f"sha3={feature_probe['sha3InstructionsEnabled']} reproducible={repeat_match}"
    )
    return 0 if repeat_match else 4


if __name__ == "__main__":
    raise SystemExit(main())
