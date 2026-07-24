#!/usr/bin/env python3
"""Fetch, verify, build, smoke-test, and inventory pinned mlkem-native."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "dependencies" / "mlkem-native.lock.json"
DEFAULT_CACHE = ROOT / ".deps" / "mlkem-native"
DEFAULT_BUILD = ROOT / "build" / "mlkem-native" / "portable-multilevel"
DEFAULT_MANIFEST = ROOT / "evidence" / "build" / "mlkem-native-portable.json"

UPSTREAM_CFLAGS = (
    "-Wall", "-Wextra", "-Werror=unused-result", "-Wpedantic", "-Werror",
    "-Wmissing-prototypes", "-Wshadow", "-Wpointer-arith",
    "-Wredundant-decls", "-Wconversion", "-Wsign-conversion",
    "-Wno-long-long", "-Wno-unknown-pragmas",
    "-Wno-unused-command-line-argument", "-O3", "-fomit-frame-pointer",
    "-std=c99", "-pedantic", "-MMD", "-Wno-redundant-decls",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_lock() -> dict:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    required = {"archiveRoot", "archiveSha256", "archiveUrl", "commit", "release"}
    missing = sorted(required - set(lock))
    if missing:
        raise RuntimeError(f"dependency lock is missing: {missing[0]}")
    return lock


def verify_archive(path: Path, expected: str) -> None:
    actual = sha256(path)
    if actual != expected:
        raise RuntimeError(f"source archive SHA-256 mismatch: expected {expected}, got {actual}")


def acquire_archive(lock: dict, cache: Path, supplied: Path | None) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f"{lock['commit']}.tar.gz"
    if supplied is not None:
        verify_archive(supplied, lock["archiveSha256"])
        if not archive.exists() or sha256(archive) != lock["archiveSha256"]:
            shutil.copyfile(supplied, archive)
    elif not archive.exists():
        temporary = archive.with_suffix(".download")
        try:
            urllib.request.urlretrieve(lock["archiveUrl"], temporary)
            verify_archive(temporary, lock["archiveSha256"])
            os.replace(temporary, archive)
        finally:
            temporary.unlink(missing_ok=True)
    verify_archive(archive, lock["archiveSha256"])
    return archive


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def extract_source(lock: dict, archive: Path, cache: Path) -> Path:
    source_parent = cache / "src"
    source = source_parent / lock["archiveRoot"]
    if source.is_dir():
        return source
    source_parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="extract-", dir=source_parent))
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                target = temporary / member.name
                if not _within(temporary, target):
                    raise RuntimeError(f"unsafe archive path: {member.name}")
                if member.isdev():
                    raise RuntimeError(f"device entry is not allowed: {member.name}")
                if member.issym():
                    link_target = target.parent / member.linkname
                    if not _within(temporary, link_target):
                        raise RuntimeError(f"unsafe archive symlink: {member.name}")
                if member.islnk():
                    link_target = temporary / member.linkname
                    if not _within(temporary, link_target):
                        raise RuntimeError(f"unsafe archive hardlink: {member.name}")
            bundle.extractall(temporary)
        extracted = temporary / lock["archiveRoot"]
        if not extracted.is_dir():
            raise RuntimeError("archive root does not match dependency lock")
        os.replace(extracted, source)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    return source


def command_version(command: str) -> str:
    process = subprocess.run(
        [command, "--version"], capture_output=True, text=True, check=False
    )
    output = process.stdout or process.stderr
    return output.splitlines()[0] if output.splitlines() else "unknown"


def build_once(source: Path, output: Path, cc: str, ar: str) -> tuple[dict, str, str]:
    shutil.rmtree(output, ignore_errors=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    example = source / "examples" / "monolithic_build_multilevel"
    relative_output = os.path.relpath(output, example)
    command = [
        "make", "-C", str(example), f"BUILD_DIR={relative_output}", f"CC={cc}",
        f"AR={ar}", "build",
    ]
    build_environment = os.environ.copy()
    build_environment["ZERO_AR_DATE"] = "1"
    built = subprocess.run(
        command, capture_output=True, text=True, check=False, env=build_environment
    )
    if built.returncode != 0:
        details = (built.stdout + built.stderr).strip()
        raise RuntimeError(f"mlkem-native build failed:\n{details}")
    binary = output / "test_binary"
    library = output / "libmlkem.a"
    bridge = output / "mlkem_native_bridge"
    bridge_source = ROOT / "backends" / "mlkem-native" / "mlkem_native_bridge.c"
    bridge_command = [
        cc, *UPSTREAM_CFLAGS, "-I", str(example), "-I",
        str(example / "mlkem_native"), str(bridge_source),
        str(library), "-o", str(bridge),
    ]
    bridge_built = subprocess.run(
        bridge_command, capture_output=True, text=True, check=False,
        env=build_environment,
    )
    if bridge_built.returncode != 0:
        details = (bridge_built.stdout + bridge_built.stderr).strip()
        raise RuntimeError(f"mlkem-native bridge build failed:\n{details}")
    tested = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    zeroize_tested = subprocess.run(
        [str(bridge), "--self-test-zeroize"], capture_output=True, text=True,
        check=True,
    )
    artifacts = {
        "libmlkem.a": {"sha256": sha256(library), "size": library.stat().st_size},
        "mlkem_native_bridge": {"sha256": sha256(bridge), "size": bridge.stat().st_size},
        "test_binary": {"sha256": sha256(binary), "size": binary.stat().st_size},
    }
    build_log = (
        built.stdout + built.stderr + "\n" + shlex.join(bridge_command) + "\n" +
        bridge_built.stdout + bridge_built.stderr
    )
    return artifacts, build_log, tested.stdout + tested.stderr + zeroize_tested.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, help="use an already-downloaded archive")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--ar", default=os.environ.get("AR", "ar"))
    args = parser.parse_args()

    lock = load_lock()
    archive = acquire_archive(lock, args.cache_dir.resolve(), args.archive)
    source = extract_source(lock, archive, args.cache_dir.resolve())
    build_dir = args.build_dir.resolve()
    first, build_log, smoke_log = build_once(source, build_dir, args.cc, args.ar)
    repeat_dir = build_dir.parent / f"{build_dir.name}-repeat"
    second, _, _ = build_once(source, repeat_dir, args.cc, args.ar)
    repeat_match = first == second
    shutil.rmtree(repeat_dir, ignore_errors=True)

    (build_dir / "build.log").write_text(build_log, encoding="utf-8")
    (build_dir / "smoke-test.log").write_text(smoke_log, encoding="utf-8")
    target = subprocess.run(
        [args.cc, "-dumpmachine"], capture_output=True, text=True, check=True
    ).stdout.strip()
    manifest = {
        "schemaVersion": 1,
        "dependency": {
            key: lock[key]
            for key in (
                "name", "release", "commit", "archiveSha256", "dependencyMethod",
                "localPatches", "sourceLicenseExpression", "selectedSourceLicense",
            )
        },
        "profile": "portable-c-multilevel",
        "parameterSets": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "configuration": {
            "MLK_CONFIG_MULTILEVEL_BUILD": True,
            "MLK_CONFIG_USE_NATIVE_BACKEND_ARITH": False,
            "MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202": False,
            "testOnlyRngLinkedOnlyIntoSmokeBinary": True,
            "ZERO_AR_DATE": "1",
        },
        "toolchain": {
            "target": target or f"{platform.machine()}-{platform.system().lower()}",
            "compiler": args.cc,
            "compilerVersion": command_version(args.cc),
            "archiver": args.ar,
            "archiverVersion": command_version(args.ar),
            "compilerFlags": list(UPSTREAM_CFLAGS),
        },
        "upstreamBuildRecipeSha256": sha256(
            source / "examples" / "monolithic_build_multilevel" / "Makefile"
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
    print(f"release={lock['release']} target={target} smoke=passed reproducible={repeat_match}")
    return 0 if repeat_match else 4


if __name__ == "__main__":
    raise SystemExit(main())
