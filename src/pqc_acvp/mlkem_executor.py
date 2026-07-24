"""ML-KEM group dispatch and per-test execution."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping

from .acvp_schema import ACVPTestCase, MLKEMTestGroup, MLKEMVectorSet
from .framework import BackendMetadata, FrameworkError, FrameworkErrorCode, StructuredError, VectorSetSummary
from .mlkem import EncapsulationEntropy, KeyGenEntropy, MLKEMACVPTestBackend, MLKEMError, parameter_metadata


_HEX = re.compile(r"^[0-9A-Fa-f]*$")


@dataclass(frozen=True)
class ExecutionResult:
    response_groups: tuple[Mapping[str, Any], ...]
    summary: VectorSetSummary


def _failure(code: FrameworkErrorCode, message: str, group: MLKEMTestGroup, test: ACVPTestCase) -> FrameworkError:
    return FrameworkError(StructuredError(code.value, "execute", message, group.function, group.tg_id, test.tc_id))


def _field(group: MLKEMTestGroup, test: ACVPTestCase, name: str) -> Any:
    value = test.values.get(name, group.shared_values.get(name))
    if value is None:
        raise _failure(FrameworkErrorCode.MISSING_FIELD, f"missing required field: {name}", group, test)
    return value


def _hex(
    group: MLKEMTestGroup,
    test: ACVPTestCase,
    name: str,
    expected_length: int | None = None,
) -> bytes:
    value = _field(group, test, name)
    if not isinstance(value, str) or len(value) % 2 or not _HEX.fullmatch(value):
        raise _failure(FrameworkErrorCode.INVALID_HEX, f"{name} must be even-length hexadecimal", group, test)
    decoded = bytes.fromhex(value)
    if expected_length is not None and len(decoded) != expected_length:
        raise _failure(
            FrameworkErrorCode.INVALID_FIELD,
            f"{name} must be {expected_length} bytes",
            group,
            test,
        )
    return decoded


def execute_test(
    backend: MLKEMACVPTestBackend,
    group: MLKEMTestGroup,
    test: ACVPTestCase,
) -> Mapping[str, Any]:
    pset = group.parameter_set
    sizes = parameter_metadata(pset).sizes
    try:
        if group.function == "keyGen":
            result = backend.keygen_deterministic(
                pset,
                KeyGenEntropy(_hex(group, test, "d", 32), _hex(group, test, "z", 32)),
            )
            return {"tcId": test.tc_id, "ek": result.encapsulation_key.hex().upper(), "dk": result.decapsulation_key.hex().upper()}
        if group.function == "encapsulation":
            result = backend.encaps_deterministic(
                pset,
                _hex(group, test, "ek", sizes.encapsulation_key),
                EncapsulationEntropy(_hex(group, test, "m", 32)),
            )
            return {"tcId": test.tc_id, "c": result.ciphertext.hex().upper(), "k": result.shared_secret.hex().upper()}
        if group.function == "decapsulation":
            secret = backend.decaps(
                pset,
                _hex(group, test, "dk", sizes.decapsulation_key),
                _hex(group, test, "c", sizes.ciphertext),
            )
            return {"tcId": test.tc_id, "k": secret.hex().upper()}
        if group.function == "encapsulationKeyCheck":
            checked = backend.check_encapsulation_key(pset, _hex(group, test, "ek"))
            return {"tcId": test.tc_id, "testPassed": checked.valid}
        if group.function == "decapsulationKeyCheck":
            checked = backend.check_decapsulation_key(pset, _hex(group, test, "dk"))
            return {"tcId": test.tc_id, "testPassed": checked.valid}
    except FrameworkError:
        raise
    except MLKEMError as exc:
        raise _failure(FrameworkErrorCode.BACKEND_ERROR, exc.message, group, test) from exc
    raise _failure(FrameworkErrorCode.UNSUPPORTED_FUNCTION, "unsupported ML-KEM function", group, test)


def execute_group(backend: MLKEMACVPTestBackend, group: MLKEMTestGroup) -> Mapping[str, Any]:
    return {"tgId": group.tg_id, "tests": [execute_test(backend, group, test) for test in group.tests]}


def execute_vector_set(
    backend: MLKEMACVPTestBackend,
    metadata: BackendMetadata,
    vector_set: MLKEMVectorSet,
) -> ExecutionResult:
    counts = Counter(group.function for group in vector_set.groups for _ in group.tests)
    tests_seen = sum(len(group.tests) for group in vector_set.groups)
    response_groups = tuple(execute_group(backend, group) for group in vector_set.groups)
    summary = VectorSetSummary(
        vector_set.algorithm, vector_set.mode, vector_set.revision, "generated",
        len(vector_set.groups), tests_seen, tests_seen, dict(counts), metadata,
    )
    return ExecutionResult(response_groups, summary)
