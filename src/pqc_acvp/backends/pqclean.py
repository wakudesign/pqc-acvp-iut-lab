"""PQClean ML-KEM contract implementation using one-shot native binaries."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from ..framework import BackendMetadata
from ..mlkem import (
    BackendFailure, EncapsulationEntropy, EncapsulationResult, ErrorCode,
    InvalidInput, KeyCheckFailure, KeyCheckResult, KeyGenEntropy, KeyPair,
    MLKEMCapabilities, MLKEMOperation, MLKEMParameterSet, parameter_metadata,
    validate_decapsulation_inputs, validate_encapsulation_output,
    validate_key_pair_output, validate_shared_secret_output,
)


class PQCleanMLKEMBackend:
    name = "PQClean"
    version = "baseline-3730b32"

    def __init__(self, bin_dir: Path, metadata: BackendMetadata, timeout_seconds: int = 30) -> None:
        self.bin_dir = bin_dir.resolve()
        self.metadata = metadata
        self.timeout_seconds = timeout_seconds
        self.capabilities = MLKEMCapabilities(
            frozenset(MLKEMParameterSet),
            frozenset(MLKEMOperation),
        )

    def _run(self, binary: str, arguments: list[str], operation: MLKEMOperation, pset: MLKEMParameterSet) -> dict[str, bytes]:
        path = self.bin_dir / binary
        if not path.is_file():
            raise BackendFailure(ErrorCode.BACKEND_FAILURE, "PQClean IUT binary is unavailable", operation=operation, parameter_set=pset)
        try:
            process = subprocess.run(
                [str(path), *arguments], capture_output=True, text=True,
                timeout=self.timeout_seconds, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BackendFailure(ErrorCode.BACKEND_FAILURE, "PQClean IUT invocation failed", operation=operation, parameter_set=pset) from exc
        if process.returncode != 0:
            raise BackendFailure(ErrorCode.BACKEND_FAILURE, "PQClean IUT returned failure", operation=operation, parameter_set=pset)
        result: dict[str, bytes] = {}
        for line in process.stdout.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            try:
                result[key.strip()] = bytes.fromhex(value.strip())
            except ValueError as exc:
                raise BackendFailure(ErrorCode.BACKEND_FAILURE, "PQClean IUT returned invalid hexadecimal", operation=operation, parameter_set=pset) from exc
        return result

    def keygen_deterministic(self, parameter_set: MLKEMParameterSet, entropy: KeyGenEntropy) -> KeyPair:
        pset = self.capabilities.require(MLKEMOperation.KEYGEN_DETERMINISTIC, parameter_set)
        values = self._run("mlkem_keygen_once", [pset.value, entropy.d.hex(), entropy.z.hex()], MLKEMOperation.KEYGEN_DETERMINISTIC, pset)
        try:
            result = KeyPair(values["ek"], values["dk"])
        except KeyError as exc:
            raise BackendFailure(ErrorCode.BACKEND_FAILURE, "PQClean keyGen output is incomplete", operation=MLKEMOperation.KEYGEN_DETERMINISTIC, parameter_set=pset) from exc
        return validate_key_pair_output(pset, result)

    def encaps_deterministic(self, parameter_set: MLKEMParameterSet, encapsulation_key: bytes, entropy: EncapsulationEntropy) -> EncapsulationResult:
        pset = self.capabilities.require(MLKEMOperation.ENCAPS_DETERMINISTIC, parameter_set)
        checked = self.check_encapsulation_key(pset, encapsulation_key)
        if not checked.valid:
            raise InvalidInput(ErrorCode.INVALID_KEY_ENCODING, "encapsulation key failed FIPS 203 input checks", operation=MLKEMOperation.ENCAPS_DETERMINISTIC, parameter_set=pset)
        values = self._run("mlkem_encap_once", [pset.value, encapsulation_key.hex(), entropy.m.hex()], MLKEMOperation.ENCAPS_DETERMINISTIC, pset)
        try:
            result = EncapsulationResult(values["c"], values["k"])
        except KeyError as exc:
            raise BackendFailure(ErrorCode.BACKEND_FAILURE, "PQClean encapsulation output is incomplete", operation=MLKEMOperation.ENCAPS_DETERMINISTIC, parameter_set=pset) from exc
        return validate_encapsulation_output(pset, result)

    def decaps(self, parameter_set: MLKEMParameterSet, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        pset = self.capabilities.require(MLKEMOperation.DECAPS, parameter_set)
        validate_decapsulation_inputs(pset, decapsulation_key, ciphertext)
        values = self._run("mlkem_decap_once", [pset.value, decapsulation_key.hex(), ciphertext.hex()], MLKEMOperation.DECAPS, pset)
        try:
            return validate_shared_secret_output(values["k"])
        except KeyError as exc:
            raise BackendFailure(ErrorCode.BACKEND_FAILURE, "PQClean decapsulation output is incomplete", operation=MLKEMOperation.DECAPS, parameter_set=pset) from exc

    def check_encapsulation_key(self, parameter_set: MLKEMParameterSet, encapsulation_key: bytes) -> KeyCheckResult:
        pset = self.capabilities.require(MLKEMOperation.ENCAPSULATION_KEY_CHECK, parameter_set)
        if not isinstance(encapsulation_key, bytes) or len(encapsulation_key) != parameter_metadata(pset).sizes.encapsulation_key:
            return KeyCheckResult(False, KeyCheckFailure.INVALID_LENGTH)
        coefficient_bytes = encapsulation_key[:-32]
        for offset in range(0, len(coefficient_bytes), 3):
            b0, b1, b2 = coefficient_bytes[offset:offset + 3]
            d0 = b0 | ((b1 & 0x0F) << 8)
            d1 = (b1 >> 4) | (b2 << 4)
            if d0 >= 3329 or d1 >= 3329:
                return KeyCheckResult(False, KeyCheckFailure.NON_CANONICAL_ENCODING)
        return KeyCheckResult(True)

    def check_decapsulation_key(self, parameter_set: MLKEMParameterSet, decapsulation_key: bytes) -> KeyCheckResult:
        pset = self.capabilities.require(MLKEMOperation.DECAPSULATION_KEY_CHECK, parameter_set)
        metadata = parameter_metadata(pset)
        if not isinstance(decapsulation_key, bytes) or len(decapsulation_key) != metadata.sizes.decapsulation_key:
            return KeyCheckResult(False, KeyCheckFailure.INVALID_LENGTH)
        k = metadata.module_rank_k
        ek_start = 384 * k
        ek_end = 768 * k + 32
        embedded_ek = decapsulation_key[ek_start:ek_end]
        embedded_hash = decapsulation_key[ek_end:ek_end + 32]
        if hashlib.sha3_256(embedded_ek).digest() != embedded_hash:
            return KeyCheckResult(False, KeyCheckFailure.HASH_MISMATCH)
        return KeyCheckResult(True)
