"""Typed ML-DSA contract for validation-only deterministic operations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Mapping, Protocol, runtime_checkable


class MLDSAParameterSet(str, Enum):
    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"

    @classmethod
    def parse(cls, value: "MLDSAParameterSet | str") -> "MLDSAParameterSet":
        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except (TypeError, ValueError) as exc:
            raise MLDSAInvalidInput(
                MLDSAErrorCode.INVALID_PARAMETER_SET,
                "unknown ML-DSA parameter set",
            ) from exc


@dataclass(frozen=True)
class MLDSASizes:
    public_key: int
    secret_key: int
    signature: int
    keygen_seed: int = 32
    signing_randomness: int = 32


@dataclass(frozen=True)
class MLDSAParameterMetadata:
    parameter_set: MLDSAParameterSet
    security_category: int
    sizes: MLDSASizes


_PARAMETERS: Mapping[MLDSAParameterSet, MLDSAParameterMetadata] = {
    MLDSAParameterSet.ML_DSA_44: MLDSAParameterMetadata(
        MLDSAParameterSet.ML_DSA_44, 2, MLDSASizes(1312, 2560, 2420)
    ),
    MLDSAParameterSet.ML_DSA_65: MLDSAParameterMetadata(
        MLDSAParameterSet.ML_DSA_65, 3, MLDSASizes(1952, 4032, 3309)
    ),
    MLDSAParameterSet.ML_DSA_87: MLDSAParameterMetadata(
        MLDSAParameterSet.ML_DSA_87, 5, MLDSASizes(2592, 4896, 4627)
    ),
}


def mldsa_parameter_metadata(
    parameter_set: MLDSAParameterSet | str,
) -> MLDSAParameterMetadata:
    return _PARAMETERS[MLDSAParameterSet.parse(parameter_set)]


class MLDSAOperation(str, Enum):
    KEYGEN = "keyGen"
    SIGGEN = "sigGen"
    SIGVER = "sigVer"


class MLDSASigningMode(str, Enum):
    DETERMINISTIC = "deterministic"
    HEDGED = "hedged"


class MLDSAErrorCode(str, Enum):
    INVALID_PARAMETER_SET = "invalidParameterSet"
    INVALID_INPUT_TYPE = "invalidInputType"
    INVALID_INPUT_LENGTH = "invalidInputLength"
    INVALID_SIGNING_RANDOMNESS = "invalidSigningRandomness"
    UNSUPPORTED_CAPABILITY = "unsupportedCapability"
    BACKEND_FAILURE = "backendFailure"


class MLDSAError(Exception):
    """Stable structured error that never includes cryptographic input."""

    def __init__(
        self,
        code: MLDSAErrorCode,
        message: str,
        *,
        operation: MLDSAOperation | None = None,
        parameter_set: MLDSAParameterSet | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.operation = operation
        self.parameter_set = parameter_set

    def to_dict(self) -> dict[str, str]:
        result = {"code": self.code.value, "message": self.message}
        if self.operation is not None:
            result["operation"] = self.operation.value
        if self.parameter_set is not None:
            result["parameterSet"] = self.parameter_set.value
        return result


class MLDSAInvalidInput(MLDSAError):
    pass


class MLDSAUnsupportedCapability(MLDSAError):
    pass


class MLDSABackendFailure(MLDSAError):
    pass


def _require_bytes(name: str, value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise MLDSAInvalidInput(
            MLDSAErrorCode.INVALID_INPUT_TYPE,
            f"{name} must be immutable bytes",
        )
    return value


def _require_exact(name: str, value: bytes, expected: int) -> bytes:
    checked = _require_bytes(name, value)
    if len(checked) != expected:
        raise MLDSAInvalidInput(
            MLDSAErrorCode.INVALID_INPUT_LENGTH,
            f"{name} must be {expected} bytes",
        )
    return checked


def validate_message_and_context(message: bytes, context: bytes) -> None:
    checked_message = _require_bytes("message", message)
    checked_context = _require_bytes("context", context)
    if not 1 <= len(checked_message) <= 8192:
        raise MLDSAInvalidInput(
            MLDSAErrorCode.INVALID_INPUT_LENGTH,
            "message must be between 1 and 8192 bytes",
        )
    if len(checked_context) > 255:
        raise MLDSAInvalidInput(
            MLDSAErrorCode.INVALID_INPUT_LENGTH,
            "context must be between 0 and 255 bytes",
        )


@dataclass(frozen=True)
class MLDSAKeyGenSeed:
    seed: bytes

    def __post_init__(self) -> None:
        _require_exact("seed", self.seed, 32)


@dataclass(frozen=True)
class MLDSASigningRandomness:
    mode: MLDSASigningMode
    rnd: bytes

    def __post_init__(self) -> None:
        _require_exact("rnd", self.rnd, 32)
        if self.mode is MLDSASigningMode.DETERMINISTIC and any(self.rnd):
            raise MLDSAInvalidInput(
                MLDSAErrorCode.INVALID_SIGNING_RANDOMNESS,
                "deterministic signing requires all-zero rnd",
            )

    @classmethod
    def deterministic(cls) -> "MLDSASigningRandomness":
        return cls(MLDSASigningMode.DETERMINISTIC, bytes(32))

    @classmethod
    def hedged(cls, rnd: bytes) -> "MLDSASigningRandomness":
        return cls(MLDSASigningMode.HEDGED, rnd)


@dataclass(frozen=True)
class MLDSAKeyPair:
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class MLDSAVerificationResult:
    valid: bool


@dataclass(frozen=True)
class MLDSACapabilities:
    parameter_sets: FrozenSet[MLDSAParameterSet]
    operations: FrozenSet[MLDSAOperation]
    signing_modes: FrozenSet[MLDSASigningMode]
    pure_external_only: bool = True

    def require(
        self,
        operation: MLDSAOperation,
        parameter_set: MLDSAParameterSet | str,
        signing_mode: MLDSASigningMode | None = None,
    ) -> MLDSAParameterSet:
        parsed = MLDSAParameterSet.parse(parameter_set)
        supported = parsed in self.parameter_sets and operation in self.operations
        if signing_mode is not None:
            supported = supported and signing_mode in self.signing_modes
        if not supported:
            raise MLDSAUnsupportedCapability(
                MLDSAErrorCode.UNSUPPORTED_CAPABILITY,
                "backend does not support the requested ML-DSA capability",
                operation=operation,
                parameter_set=parsed,
            )
        return parsed


@runtime_checkable
class MLDSAACVPTestBackend(Protocol):
    """Pure/external validation API; caller-supplied rnd is ACVP-only."""

    name: str
    version: str
    capabilities: MLDSACapabilities

    def keygen_deterministic(
        self, parameter_set: MLDSAParameterSet, seed: MLDSAKeyGenSeed
    ) -> MLDSAKeyPair: ...

    def sign_pure(
        self,
        parameter_set: MLDSAParameterSet,
        secret_key: bytes,
        message: bytes,
        context: bytes,
        randomness: MLDSASigningRandomness,
    ) -> bytes: ...

    def verify_pure(
        self,
        parameter_set: MLDSAParameterSet,
        public_key: bytes,
        message: bytes,
        context: bytes,
        signature: bytes,
    ) -> MLDSAVerificationResult: ...


def validate_key_pair_output(
    parameter_set: MLDSAParameterSet | str, result: MLDSAKeyPair
) -> MLDSAKeyPair:
    sizes = mldsa_parameter_metadata(parameter_set).sizes
    try:
        _require_exact("public key", result.public_key, sizes.public_key)
        _require_exact("secret key", result.secret_key, sizes.secret_key)
    except MLDSAInvalidInput as exc:
        raise MLDSABackendFailure(
            MLDSAErrorCode.BACKEND_FAILURE,
            "backend returned an invalid ML-DSA key pair",
        ) from exc
    return result


def validate_signing_inputs(
    parameter_set: MLDSAParameterSet | str,
    secret_key: bytes,
    message: bytes,
    context: bytes,
) -> MLDSAParameterSet:
    parsed = MLDSAParameterSet.parse(parameter_set)
    _require_exact("secret key", secret_key, mldsa_parameter_metadata(parsed).sizes.secret_key)
    validate_message_and_context(message, context)
    return parsed


def validate_signature_output(
    parameter_set: MLDSAParameterSet | str, signature: bytes
) -> bytes:
    try:
        return _require_exact(
            "signature", signature, mldsa_parameter_metadata(parameter_set).sizes.signature
        )
    except MLDSAInvalidInput as exc:
        raise MLDSABackendFailure(
            MLDSAErrorCode.BACKEND_FAILURE,
            "backend returned an invalid ML-DSA signature",
        ) from exc


def validate_verification_inputs(
    parameter_set: MLDSAParameterSet | str,
    public_key: bytes,
    message: bytes,
    context: bytes,
    signature: bytes,
) -> MLDSAParameterSet:
    parsed = MLDSAParameterSet.parse(parameter_set)
    sizes = mldsa_parameter_metadata(parsed).sizes
    _require_exact("public key", public_key, sizes.public_key)
    _require_exact("signature", signature, sizes.signature)
    validate_message_and_context(message, context)
    return parsed
