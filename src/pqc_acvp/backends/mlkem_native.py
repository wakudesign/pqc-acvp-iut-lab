"""ACVP-only adapter for the owner-authored mlkem-native one-shot bridge."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from ..framework import BackendMetadata
from ..mlkem import (
    BackendFailure,
    EncapsulationEntropy,
    EncapsulationResult,
    ErrorCode,
    InvalidInput,
    KeyCheckFailure,
    KeyCheckResult,
    KeyGenEntropy,
    KeyPair,
    MLKEMCapabilities,
    MLKEMOperation,
    MLKEMParameterSet,
    parameter_metadata,
    validate_decapsulation_inputs,
    validate_encapsulation_output,
    validate_key_pair_output,
    validate_shared_secret_output,
)


_LEVEL = {
    MLKEMParameterSet.ML_KEM_512: "512",
    MLKEMParameterSet.ML_KEM_768: "768",
    MLKEMParameterSet.ML_KEM_1024: "1024",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def metadata_from_build_manifest(path: Path) -> BackendMetadata:
    data = json.loads(path.read_text(encoding="utf-8"))
    dependency = data["dependency"]
    toolchain = data["toolchain"]
    configuration = data["configuration"]
    flags = tuple(toolchain["compilerFlags"]) + (
        f"MLK_CONFIG_MULTILEVEL_BUILD={int(configuration['MLK_CONFIG_MULTILEVEL_BUILD'])}",
        f"MLK_CONFIG_USE_NATIVE_BACKEND_ARITH={int(configuration['MLK_CONFIG_USE_NATIVE_BACKEND_ARITH'])}",
        f"MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202={int(configuration['MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202'])}",
        f"ZERO_AR_DATE={configuration['ZERO_AR_DATE']}",
    )
    return BackendMetadata(
        name="mlkem-native",
        version=dependency["release"],
        commit=dependency["commit"],
        target=toolchain["target"],
        compiler=f"{toolchain['compiler']}: {toolchain['compilerVersion']}",
        flags=flags,
    )


class MLKEMNativeBackend:
    """Deterministic validation backend; not a production RNG API."""

    name = "mlkem-native"

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
        self.capabilities = MLKEMCapabilities(
            frozenset(MLKEMParameterSet), frozenset(MLKEMOperation)
        )

    @classmethod
    def from_build_manifest(
        cls,
        bridge_path: Path,
        manifest_path: Path,
        *,
        timeout_seconds: int = 30,
    ) -> "MLKEMNativeBackend":
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not data.get("repeatBuildMatched") or not data.get("bridgeZeroizeSelfTestPassed"):
            raise BackendFailure(
                ErrorCode.BACKEND_FAILURE,
                "mlkem-native build manifest did not pass required gates",
            )
        expected = data["artifacts"]["mlkem_native_bridge"]["sha256"]
        if not bridge_path.is_file() or _sha256(bridge_path) != expected:
            raise BackendFailure(
                ErrorCode.BACKEND_FAILURE,
                "mlkem-native bridge does not match the build manifest",
            )
        metadata = metadata_from_build_manifest(manifest_path)
        return cls(
            bridge_path,
            metadata,
            version=data["dependency"]["release"],
            timeout_seconds=timeout_seconds,
        )

    def _invoke(
        self,
        operation: str,
        parameter_set: MLKEMParameterSet,
        inputs: Sequence[bytes],
    ) -> Mapping[str, str]:
        if not self.bridge_path.is_file():
            raise BackendFailure(
                ErrorCode.BACKEND_FAILURE,
                "mlkem-native bridge is unavailable",
                parameter_set=parameter_set,
            )
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
            raise BackendFailure(
                ErrorCode.BACKEND_FAILURE,
                "mlkem-native bridge invocation failed",
                parameter_set=parameter_set,
            ) from exc
        if process.returncode != 0:
            raise BackendFailure(
                ErrorCode.BACKEND_FAILURE,
                "mlkem-native operation failed",
                parameter_set=parameter_set,
            )
        result: dict[str, str] = {}
        for line in process.stdout.splitlines():
            if "=" not in line:
                raise BackendFailure(
                    ErrorCode.BACKEND_FAILURE,
                    "mlkem-native bridge returned malformed output",
                    parameter_set=parameter_set,
                )
            key, value = line.split("=", 1)
            if key in result:
                raise BackendFailure(
                    ErrorCode.BACKEND_FAILURE,
                    "mlkem-native bridge returned duplicate output",
                    parameter_set=parameter_set,
                )
            result[key] = value
        return result

    @staticmethod
    def _decode(values: Mapping[str, str], key: str) -> bytes:
        try:
            encoded = values[key]
            if len(encoded) % 2:
                raise ValueError
            return bytes.fromhex(encoded)
        except (KeyError, ValueError) as exc:
            raise BackendFailure(
                ErrorCode.BACKEND_FAILURE,
                "mlkem-native bridge returned invalid output",
            ) from exc

    @staticmethod
    def _require_keys(values: Mapping[str, str], expected: set[str]) -> None:
        if set(values) != expected:
            raise BackendFailure(
                ErrorCode.BACKEND_FAILURE,
                "mlkem-native bridge returned an unexpected output schema",
            )

    def keygen_deterministic(
        self, parameter_set: MLKEMParameterSet, entropy: KeyGenEntropy
    ) -> KeyPair:
        parsed = self.capabilities.require(
            MLKEMOperation.KEYGEN_DETERMINISTIC, parameter_set
        )
        values = self._invoke("keygen", parsed, (entropy.d, entropy.z))
        self._require_keys(values, {"ek", "dk"})
        return validate_key_pair_output(
            parsed, KeyPair(self._decode(values, "ek"), self._decode(values, "dk"))
        )

    def encaps_deterministic(
        self,
        parameter_set: MLKEMParameterSet,
        encapsulation_key: bytes,
        entropy: EncapsulationEntropy,
    ) -> EncapsulationResult:
        parsed = self.capabilities.require(
            MLKEMOperation.ENCAPS_DETERMINISTIC, parameter_set
        )
        checked = self.check_encapsulation_key(parsed, encapsulation_key)
        if not checked.valid:
            code = (
                ErrorCode.INVALID_INPUT_LENGTH
                if checked.failure is KeyCheckFailure.INVALID_LENGTH
                else ErrorCode.INVALID_KEY_ENCODING
            )
            raise InvalidInput(
                code,
                "encapsulation key failed FIPS 203 input checks",
                operation=MLKEMOperation.ENCAPS_DETERMINISTIC,
                parameter_set=parsed,
            )
        values = self._invoke("encaps", parsed, (encapsulation_key, entropy.m))
        self._require_keys(values, {"c", "k"})
        return validate_encapsulation_output(
            parsed,
            EncapsulationResult(self._decode(values, "c"), self._decode(values, "k")),
        )

    def decaps(
        self,
        parameter_set: MLKEMParameterSet,
        decapsulation_key: bytes,
        ciphertext: bytes,
    ) -> bytes:
        parsed = self.capabilities.require(MLKEMOperation.DECAPS, parameter_set)
        validate_decapsulation_inputs(parsed, decapsulation_key, ciphertext)
        if not self.check_decapsulation_key(parsed, decapsulation_key).valid:
            raise InvalidInput(
                ErrorCode.INVALID_KEY_ENCODING,
                "decapsulation key failed FIPS 203 input checks",
                operation=MLKEMOperation.DECAPS,
                parameter_set=parsed,
            )
        values = self._invoke("decaps", parsed, (decapsulation_key, ciphertext))
        self._require_keys(values, {"k"})
        return validate_shared_secret_output(self._decode(values, "k"))

    def check_encapsulation_key(
        self, parameter_set: MLKEMParameterSet, encapsulation_key: bytes
    ) -> KeyCheckResult:
        parsed = self.capabilities.require(
            MLKEMOperation.ENCAPSULATION_KEY_CHECK, parameter_set
        )
        if not isinstance(encapsulation_key, bytes) or len(encapsulation_key) != parameter_metadata(parsed).sizes.encapsulation_key:
            return KeyCheckResult(False, KeyCheckFailure.INVALID_LENGTH)
        values = self._invoke("check-pk", parsed, (encapsulation_key,))
        if values == {"valid": "1"}:
            return KeyCheckResult(True)
        if values == {"valid": "0"}:
            return KeyCheckResult(False, KeyCheckFailure.NON_CANONICAL_ENCODING)
        raise BackendFailure(
            ErrorCode.BACKEND_FAILURE, "mlkem-native bridge returned invalid key-check output"
        )

    def check_decapsulation_key(
        self, parameter_set: MLKEMParameterSet, decapsulation_key: bytes
    ) -> KeyCheckResult:
        parsed = self.capabilities.require(
            MLKEMOperation.DECAPSULATION_KEY_CHECK, parameter_set
        )
        if not isinstance(decapsulation_key, bytes) or len(decapsulation_key) != parameter_metadata(parsed).sizes.decapsulation_key:
            return KeyCheckResult(False, KeyCheckFailure.INVALID_LENGTH)
        values = self._invoke("check-sk", parsed, (decapsulation_key,))
        if values == {"valid": "1"}:
            return KeyCheckResult(True)
        if values == {"valid": "0"}:
            return KeyCheckResult(False, KeyCheckFailure.HASH_MISMATCH)
        raise BackendFailure(
            ErrorCode.BACKEND_FAILURE, "mlkem-native bridge returned invalid key-check output"
        )
