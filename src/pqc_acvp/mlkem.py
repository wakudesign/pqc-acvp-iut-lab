"""Typed ML-KEM backend contracts for ACVP and production boundaries.

The deterministic interfaces in this module represent FIPS 203 internal
functions exposed only to validation tooling. Production applications must use
``MLKEMProductionBackend``, whose key generation and encapsulation APIs do not
accept caller-supplied entropy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Mapping, Protocol, runtime_checkable


class MLKEMParameterSet(str, Enum):
    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"

    @classmethod
    def parse(cls, value: "MLKEMParameterSet | str") -> "MLKEMParameterSet":
        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except (TypeError, ValueError) as exc:
            raise InvalidInput(
                ErrorCode.INVALID_PARAMETER_SET,
                "unknown ML-KEM parameter set",
            ) from exc


@dataclass(frozen=True)
class MLKEMSizes:
    encapsulation_key: int
    decapsulation_key: int
    ciphertext: int
    shared_secret: int = 32
    keygen_d: int = 32
    keygen_z: int = 32
    encapsulation_randomness: int = 32


@dataclass(frozen=True)
class MLKEMParameterMetadata:
    parameter_set: MLKEMParameterSet
    security_category: int
    module_rank_k: int
    sizes: MLKEMSizes


_PARAMETERS: Mapping[MLKEMParameterSet, MLKEMParameterMetadata] = {
    MLKEMParameterSet.ML_KEM_512: MLKEMParameterMetadata(
        MLKEMParameterSet.ML_KEM_512,
        security_category=1,
        module_rank_k=2,
        sizes=MLKEMSizes(800, 1632, 768),
    ),
    MLKEMParameterSet.ML_KEM_768: MLKEMParameterMetadata(
        MLKEMParameterSet.ML_KEM_768,
        security_category=3,
        module_rank_k=3,
        sizes=MLKEMSizes(1184, 2400, 1088),
    ),
    MLKEMParameterSet.ML_KEM_1024: MLKEMParameterMetadata(
        MLKEMParameterSet.ML_KEM_1024,
        security_category=5,
        module_rank_k=4,
        sizes=MLKEMSizes(1568, 3168, 1568),
    ),
}


def parameter_metadata(
    parameter_set: MLKEMParameterSet | str,
) -> MLKEMParameterMetadata:
    return _PARAMETERS[MLKEMParameterSet.parse(parameter_set)]


class MLKEMOperation(str, Enum):
    KEYGEN_DETERMINISTIC = "keyGenDeterministic"
    ENCAPS_DETERMINISTIC = "encapsDeterministic"
    DECAPS = "decaps"
    ENCAPSULATION_KEY_CHECK = "encapsulationKeyCheck"
    DECAPSULATION_KEY_CHECK = "decapsulationKeyCheck"


class ErrorCode(str, Enum):
    INVALID_PARAMETER_SET = "invalidParameterSet"
    INVALID_INPUT_TYPE = "invalidInputType"
    INVALID_INPUT_LENGTH = "invalidInputLength"
    INVALID_KEY_ENCODING = "invalidKeyEncoding"
    UNSUPPORTED_CAPABILITY = "unsupportedCapability"
    BACKEND_FAILURE = "backendFailure"
    RNG_FAILURE = "rngFailure"


class MLKEMError(Exception):
    """Base error with a stable, non-secret structured representation."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        operation: MLKEMOperation | None = None,
        parameter_set: MLKEMParameterSet | None = None,
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


class InvalidInput(MLKEMError):
    pass


class UnsupportedCapability(MLKEMError):
    pass


class BackendFailure(MLKEMError):
    pass


def _require_bytes(name: str, value: bytes, expected_length: int) -> bytes:
    if not isinstance(value, bytes):
        raise InvalidInput(
            ErrorCode.INVALID_INPUT_TYPE,
            f"{name} must be immutable bytes",
        )
    if len(value) != expected_length:
        raise InvalidInput(
            ErrorCode.INVALID_INPUT_LENGTH,
            f"{name} must be {expected_length} bytes",
        )
    return value


@dataclass(frozen=True)
class KeyGenEntropy:
    """ACVP-only entropy for ML-KEM.KeyGen_internal(d, z)."""

    d: bytes
    z: bytes

    def __post_init__(self) -> None:
        _require_bytes("d", self.d, 32)
        _require_bytes("z", self.z, 32)

    @classmethod
    def checked(cls, d: bytes, z: bytes) -> "KeyGenEntropy":
        return cls(d, z)


@dataclass(frozen=True)
class EncapsulationEntropy:
    """ACVP-only 32-byte m for ML-KEM.Encaps_internal(ek, m)."""

    m: bytes

    def __post_init__(self) -> None:
        _require_bytes("m", self.m, 32)

    @classmethod
    def checked(cls, m: bytes) -> "EncapsulationEntropy":
        return cls(m)


@dataclass(frozen=True)
class KeyPair:
    encapsulation_key: bytes
    decapsulation_key: bytes


@dataclass(frozen=True)
class EncapsulationResult:
    ciphertext: bytes
    shared_secret: bytes


class KeyCheckFailure(str, Enum):
    INVALID_LENGTH = "invalidLength"
    NON_CANONICAL_ENCODING = "nonCanonicalEncoding"
    HASH_MISMATCH = "hashMismatch"


@dataclass(frozen=True)
class KeyCheckResult:
    valid: bool
    failure: KeyCheckFailure | None = None

    def __post_init__(self) -> None:
        if self.valid and self.failure is not None:
            raise ValueError("valid key check cannot carry a failure reason")
        if not self.valid and self.failure is None:
            raise ValueError("invalid key check requires a failure reason")


@dataclass(frozen=True)
class MLKEMCapabilities:
    parameter_sets: FrozenSet[MLKEMParameterSet]
    operations: FrozenSet[MLKEMOperation]

    def require(
        self,
        operation: MLKEMOperation,
        parameter_set: MLKEMParameterSet | str,
    ) -> MLKEMParameterSet:
        parsed = MLKEMParameterSet.parse(parameter_set)
        if parsed not in self.parameter_sets or operation not in self.operations:
            raise UnsupportedCapability(
                ErrorCode.UNSUPPORTED_CAPABILITY,
                "backend does not support the requested ML-KEM capability",
                operation=operation,
                parameter_set=parsed,
            )
        return parsed


@runtime_checkable
class MLKEMACVPTestBackend(Protocol):
    """Validation-only deterministic backend interface.

    Implementations must translate native-library failures into ``MLKEMError``
    subclasses and must validate output sizes before returning.
    """

    name: str
    version: str
    capabilities: MLKEMCapabilities

    def keygen_deterministic(
        self,
        parameter_set: MLKEMParameterSet,
        entropy: KeyGenEntropy,
    ) -> KeyPair: ...

    def encaps_deterministic(
        self,
        parameter_set: MLKEMParameterSet,
        encapsulation_key: bytes,
        entropy: EncapsulationEntropy,
    ) -> EncapsulationResult: ...

    def decaps(
        self,
        parameter_set: MLKEMParameterSet,
        decapsulation_key: bytes,
        ciphertext: bytes,
    ) -> bytes:
        """Return 32 bytes for every well-formed ciphertext.

        A same-length modified ciphertext follows FIPS 203 implicit rejection;
        it is not an ``InvalidInput`` or ``BackendFailure`` and this interface
        intentionally exposes no ciphertext-validity flag.
        """
        ...

    def check_encapsulation_key(
        self,
        parameter_set: MLKEMParameterSet,
        encapsulation_key: bytes,
    ) -> KeyCheckResult: ...

    def check_decapsulation_key(
        self,
        parameter_set: MLKEMParameterSet,
        decapsulation_key: bytes,
    ) -> KeyCheckResult: ...


@runtime_checkable
class MLKEMProductionBackend(Protocol):
    """Production boundary: entropy is generated inside the crypto module."""

    name: str
    version: str

    def keygen(self, parameter_set: MLKEMParameterSet) -> KeyPair: ...

    def encaps(
        self,
        parameter_set: MLKEMParameterSet,
        encapsulation_key: bytes,
    ) -> EncapsulationResult: ...

    def decaps(
        self,
        parameter_set: MLKEMParameterSet,
        decapsulation_key: bytes,
        ciphertext: bytes,
    ) -> bytes: ...


def validate_key_pair_output(
    parameter_set: MLKEMParameterSet | str,
    result: KeyPair,
) -> KeyPair:
    sizes = parameter_metadata(parameter_set).sizes
    try:
        _require_bytes("encapsulation key", result.encapsulation_key, sizes.encapsulation_key)
        _require_bytes("decapsulation key", result.decapsulation_key, sizes.decapsulation_key)
    except InvalidInput as exc:
        raise BackendFailure(ErrorCode.BACKEND_FAILURE, "backend returned an invalid key pair") from exc
    return result


def validate_encapsulation_output(
    parameter_set: MLKEMParameterSet | str,
    result: EncapsulationResult,
) -> EncapsulationResult:
    sizes = parameter_metadata(parameter_set).sizes
    try:
        _require_bytes("ciphertext", result.ciphertext, sizes.ciphertext)
        _require_bytes("shared secret", result.shared_secret, sizes.shared_secret)
    except InvalidInput as exc:
        raise BackendFailure(ErrorCode.BACKEND_FAILURE, "backend returned an invalid encapsulation result") from exc
    return result


def validate_decapsulation_inputs(
    parameter_set: MLKEMParameterSet | str,
    decapsulation_key: bytes,
    ciphertext: bytes,
) -> MLKEMParameterSet:
    parsed = MLKEMParameterSet.parse(parameter_set)
    sizes = parameter_metadata(parsed).sizes
    _require_bytes("decapsulation key", decapsulation_key, sizes.decapsulation_key)
    _require_bytes("ciphertext", ciphertext, sizes.ciphertext)
    return parsed


def validate_shared_secret_output(shared_secret: bytes) -> bytes:
    try:
        return _require_bytes("shared secret", shared_secret, 32)
    except InvalidInput as exc:
        raise BackendFailure(ErrorCode.BACKEND_FAILURE, "backend returned an invalid shared secret") from exc
