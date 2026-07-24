"""ML-DSA group dispatch and per-test execution."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping

from .framework import BackendMetadata, FrameworkError, FrameworkErrorCode, StructuredError, VectorSetSummary
from .mldsa import MLDSAACVPTestBackend, MLDSAError, MLDSAKeyGenSeed, MLDSASigningRandomness, mldsa_parameter_metadata, validate_message_and_context
from .mldsa_schema import MLDSATestCase, MLDSATestGroup, MLDSAVectorSet


_HEX = re.compile(r"^[0-9A-Fa-f]*$")


@dataclass(frozen=True)
class MLDSAExecutionResult:
    response_groups: tuple[Mapping[str, Any], ...]
    summary: VectorSetSummary


def _failure(code: FrameworkErrorCode, message: str, group: MLDSATestGroup, test: MLDSATestCase) -> FrameworkError:
    return FrameworkError(StructuredError(code.value, "execute", message, group.mode, group.tg_id, test.tc_id))


def _hex(group: MLDSATestGroup, test: MLDSATestCase, name: str, expected_length: int | None = None) -> bytes:
    if name not in test.values:
        raise _failure(FrameworkErrorCode.MISSING_FIELD, f"missing required field: {name}", group, test)
    value = test.values[name]
    if not isinstance(value, str) or len(value) % 2 or not _HEX.fullmatch(value):
        raise _failure(FrameworkErrorCode.INVALID_HEX, f"{name} must be even-length hexadecimal", group, test)
    decoded = bytes.fromhex(value)
    if expected_length is not None and len(decoded) != expected_length:
        raise _failure(FrameworkErrorCode.INVALID_FIELD, f"{name} must be {expected_length} bytes", group, test)
    return decoded


def execute_mldsa_test(backend: MLDSAACVPTestBackend, group: MLDSATestGroup, test: MLDSATestCase) -> Mapping[str, Any]:
    sizes = mldsa_parameter_metadata(group.parameter_set).sizes
    try:
        if group.mode == "keyGen":
            result = backend.keygen_deterministic(group.parameter_set, MLDSAKeyGenSeed(_hex(group, test, "seed", 32)))
            return {"tcId": test.tc_id, "pk": result.public_key.hex().upper(), "sk": result.secret_key.hex().upper()}
        if group.mode == "sigGen":
            randomness = (
                MLDSASigningRandomness.deterministic()
                if group.deterministic
                else MLDSASigningRandomness.hedged(_hex(group, test, "rnd", 32))
            )
            message = _hex(group, test, "message")
            context = _hex(group, test, "context")
            validate_message_and_context(message, context)
            signature = backend.sign_pure(
                group.parameter_set,
                _hex(group, test, "sk", sizes.secret_key),
                message,
                context,
                randomness,
            )
            return {"tcId": test.tc_id, "signature": signature.hex().upper()}
        if group.mode == "sigVer":
            message = _hex(group, test, "message")
            context = _hex(group, test, "context")
            validate_message_and_context(message, context)
            result = backend.verify_pure(
                group.parameter_set,
                _hex(group, test, "pk", sizes.public_key),
                message,
                context,
                _hex(group, test, "signature", sizes.signature),
            )
            return {"tcId": test.tc_id, "testPassed": result.valid}
    except FrameworkError:
        raise
    except MLDSAError as exc:
        raise _failure(FrameworkErrorCode.BACKEND_ERROR, exc.message, group, test) from exc
    raise _failure(FrameworkErrorCode.UNSUPPORTED_FUNCTION, "unsupported ML-DSA operation", group, test)


def execute_mldsa_group(backend: MLDSAACVPTestBackend, group: MLDSATestGroup) -> Mapping[str, Any]:
    return {"tgId": group.tg_id, "tests": [execute_mldsa_test(backend, group, test) for test in group.tests]}


def execute_mldsa_vector_set(backend: MLDSAACVPTestBackend, metadata: BackendMetadata, vector_set: MLDSAVectorSet) -> MLDSAExecutionResult:
    tests_seen = sum(len(group.tests) for group in vector_set.groups)
    response_groups = tuple(execute_mldsa_group(backend, group) for group in vector_set.groups)
    counts = Counter(group.mode for group in vector_set.groups for _ in group.tests)
    summary = VectorSetSummary(
        vector_set.algorithm, vector_set.mode, vector_set.revision, "generated",
        len(vector_set.groups), tests_seen, tests_seen, dict(counts), metadata,
    )
    return MLDSAExecutionResult(response_groups, summary)
