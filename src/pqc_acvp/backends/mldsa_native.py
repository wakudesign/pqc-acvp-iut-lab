"""ACVP-only adapter for the owner-authored mldsa-native bridge."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from ..framework import BackendMetadata
from ..mldsa import (
    MLDSAACVPTestBackend,
    MLDSABackendFailure,
    MLDSACapabilities,
    MLDSAErrorCode,
    MLDSAKeyGenSeed,
    MLDSAKeyPair,
    MLDSAOperation,
    MLDSAParameterSet,
    MLDSASigningRandomness,
    MLDSAVerificationResult,
    validate_key_pair_output,
    validate_signature_output,
    validate_signing_inputs,
    validate_verification_inputs,
)


_LEVEL = {
    MLDSAParameterSet.ML_DSA_44: "44",
    MLDSAParameterSet.ML_DSA_65: "65",
    MLDSAParameterSet.ML_DSA_87: "87",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def mldsa_metadata_from_build_manifest(path: Path) -> BackendMetadata:
    data = json.loads(path.read_text(encoding="utf-8"))
    dependency = data["dependency"]
    toolchain = data["toolchain"]
    configuration = data["configuration"]
    flags = tuple(toolchain["compilerFlags"]) + (
        f"MLD_CONFIG_MULTILEVEL_BUILD={int(configuration['MLD_CONFIG_MULTILEVEL_BUILD'])}",
        f"MLD_CONFIG_USE_NATIVE_BACKEND_ARITH={int(configuration['MLD_CONFIG_USE_NATIVE_BACKEND_ARITH'])}",
        f"MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202={int(configuration['MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202'])}",
        f"ZERO_AR_DATE={configuration['ZERO_AR_DATE']}",
    )
    return BackendMetadata(
        name="mldsa-native",
        version=dependency["release"],
        commit=dependency["commit"],
        target=toolchain["target"],
        compiler=f"{toolchain['compiler']}: {toolchain['compilerVersion']}",
        flags=flags,
    )


class MLDSANativeBackend(MLDSAACVPTestBackend):
    """Pure/external validation backend; not a production signing API."""

    name = "mldsa-native"

    def __init__(
        self,
        bridge_path: Path,
        metadata: BackendMetadata,
        *,
        version: str,
        timeout_seconds: int = 30,
    ) -> None:
        self.bridge_path = bridge_path.resolve()
        self.metadata = metadata
        self.version = version
        self.timeout_seconds = timeout_seconds
        self.capabilities = MLDSACapabilities(
            frozenset(MLDSAParameterSet),
            frozenset(MLDSAOperation),
            frozenset({
                MLDSASigningRandomness.deterministic().mode,
                MLDSASigningRandomness.hedged(bytes(32)).mode,
            }),
        )

    @classmethod
    def from_build_manifest(
        cls,
        bridge_path: Path,
        manifest_path: Path,
        *,
        timeout_seconds: int = 30,
    ) -> "MLDSANativeBackend":
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        required_gates = (
            data.get("repeatBuildMatched"),
            data.get("bridgeZeroizeSelfTestPassed"),
            data.get("nativeSymbolScanPassed"),
        )
        if not all(required_gates):
            raise MLDSABackendFailure(
                MLDSAErrorCode.BACKEND_FAILURE,
                "mldsa-native build manifest did not pass required gates",
            )
        expected = data["artifacts"]["mldsa_native_bridge"]["sha256"]
        if not bridge_path.is_file() or _sha256(bridge_path) != expected:
            raise MLDSABackendFailure(
                MLDSAErrorCode.BACKEND_FAILURE,
                "mldsa-native bridge does not match the build manifest",
            )
        return cls(
            bridge_path,
            mldsa_metadata_from_build_manifest(manifest_path),
            version=data["dependency"]["release"],
            timeout_seconds=timeout_seconds,
        )

    def _invoke(
        self,
        operation: str,
        parameter_set: MLDSAParameterSet,
        inputs: Sequence[bytes],
    ) -> Mapping[str, str]:
        standard_input = "".join(value.hex() + "\n" for value in inputs)
        try:
            process = subprocess.run(
                [str(self.bridge_path), operation, _LEVEL[parameter_set]],
                input=standard_input,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise MLDSABackendFailure(
                MLDSAErrorCode.BACKEND_FAILURE,
                "mldsa-native bridge invocation failed",
                parameter_set=parameter_set,
            ) from exc
        if process.returncode != 0:
            raise MLDSABackendFailure(
                MLDSAErrorCode.BACKEND_FAILURE,
                "mldsa-native operation failed",
                parameter_set=parameter_set,
            )
        result: dict[str, str] = {}
        for line in process.stdout.splitlines():
            if "=" not in line:
                raise MLDSABackendFailure(
                    MLDSAErrorCode.BACKEND_FAILURE,
                    "mldsa-native bridge returned malformed output",
                )
            key, value = line.split("=", 1)
            if key in result:
                raise MLDSABackendFailure(
                    MLDSAErrorCode.BACKEND_FAILURE,
                    "mldsa-native bridge returned duplicate output",
                )
            result[key] = value
        return result

    @staticmethod
    def _require_keys(values: Mapping[str, str], expected: set[str]) -> None:
        if set(values) != expected:
            raise MLDSABackendFailure(
                MLDSAErrorCode.BACKEND_FAILURE,
                "mldsa-native bridge returned an unexpected output schema",
            )

    @staticmethod
    def _decode(values: Mapping[str, str], key: str) -> bytes:
        try:
            encoded = values[key]
            if len(encoded) % 2:
                raise ValueError
            return bytes.fromhex(encoded)
        except (KeyError, ValueError) as exc:
            raise MLDSABackendFailure(
                MLDSAErrorCode.BACKEND_FAILURE,
                "mldsa-native bridge returned invalid output",
            ) from exc

    def keygen_deterministic(
        self, parameter_set: MLDSAParameterSet, seed: MLDSAKeyGenSeed
    ) -> MLDSAKeyPair:
        parsed = self.capabilities.require(MLDSAOperation.KEYGEN, parameter_set)
        values = self._invoke("keygen", parsed, (seed.seed,))
        self._require_keys(values, {"pk", "sk"})
        return validate_key_pair_output(
            parsed,
            MLDSAKeyPair(self._decode(values, "pk"), self._decode(values, "sk")),
        )

    def sign_pure(
        self,
        parameter_set: MLDSAParameterSet,
        secret_key: bytes,
        message: bytes,
        context: bytes,
        randomness: MLDSASigningRandomness,
    ) -> bytes:
        parsed = self.capabilities.require(
            MLDSAOperation.SIGGEN, parameter_set, randomness.mode
        )
        validate_signing_inputs(parsed, secret_key, message, context)
        values = self._invoke(
            "siggen", parsed, (secret_key, message, context, randomness.rnd)
        )
        self._require_keys(values, {"signature"})
        return validate_signature_output(parsed, self._decode(values, "signature"))

    def verify_pure(
        self,
        parameter_set: MLDSAParameterSet,
        public_key: bytes,
        message: bytes,
        context: bytes,
        signature: bytes,
    ) -> MLDSAVerificationResult:
        parsed = self.capabilities.require(MLDSAOperation.SIGVER, parameter_set)
        validate_verification_inputs(parsed, public_key, message, context, signature)
        values = self._invoke(
            "sigver", parsed, (public_key, message, context, signature)
        )
        if values == {"testPassed": "1"}:
            return MLDSAVerificationResult(True)
        if values == {"testPassed": "0"}:
            return MLDSAVerificationResult(False)
        raise MLDSABackendFailure(
            MLDSAErrorCode.BACKEND_FAILURE,
            "mldsa-native bridge returned invalid verification output",
        )
