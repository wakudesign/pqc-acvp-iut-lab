"""Strict parsing of the ML-KEM subset of ACVP JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .framework import FrameworkError, FrameworkErrorCode, StructuredError
from .mlkem import MLKEMError, MLKEMParameterSet


@dataclass(frozen=True)
class ACVPTestCase:
    tc_id: int
    values: Mapping[str, Any]


@dataclass(frozen=True)
class MLKEMTestGroup:
    tg_id: int
    parameter_set: MLKEMParameterSet
    test_type: str
    function: str
    shared_values: Mapping[str, Any]
    tests: tuple[ACVPTestCase, ...]


@dataclass(frozen=True)
class MLKEMVectorSet:
    version: Mapping[str, Any] | None
    vs_id: int
    algorithm: str
    mode: str
    revision: str
    groups: tuple[MLKEMTestGroup, ...]


def _error(code: FrameworkErrorCode, message: str, *, tg_id: int | None = None) -> FrameworkError:
    return FrameworkError(StructuredError(code.value, "parse", message, tg_id=tg_id))


def _required(mapping: Mapping[str, Any], key: str, *, tg_id: int | None = None) -> Any:
    if key not in mapping:
        raise _error(FrameworkErrorCode.MISSING_FIELD, f"missing required field: {key}", tg_id=tg_id)
    return mapping[key]


def _reject_unknown(
    mapping: Mapping[str, Any],
    allowed: set[str],
    *,
    context: str,
    tg_id: int | None = None,
) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise _error(
            FrameworkErrorCode.UNKNOWN_FIELD,
            f"unknown {context} field: {unknown[0]}",
            tg_id=tg_id,
        )


def parse_mlkem_document(text: str) -> MLKEMVectorSet:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _error(FrameworkErrorCode.INVALID_DOCUMENT, "input is not valid JSON") from exc

    version = None
    if isinstance(raw, list):
        if len(raw) != 2 or not isinstance(raw[0], dict) or not isinstance(raw[1], dict):
            raise _error(FrameworkErrorCode.INVALID_DOCUMENT, "invalid ACVP wrapper")
        version, payload = raw
        _reject_unknown(version, {"acvVersion"}, context="version")
        if not isinstance(_required(version, "acvVersion"), str):
            raise _error(FrameworkErrorCode.INVALID_FIELD, "acvVersion must be a string")
    elif isinstance(raw, dict):
        payload = raw
    else:
        raise _error(FrameworkErrorCode.INVALID_DOCUMENT, "ACVP root must be an object or two-item array")

    _reject_unknown(
        payload,
        {"algorithm", "isSample", "mode", "revision", "testGroups", "vsId"},
        context="vector set",
    )

    algorithm = _required(payload, "algorithm")
    if algorithm != "ML-KEM":
        raise _error(FrameworkErrorCode.UNSUPPORTED_ALGORITHM, "only ML-KEM is supported")
    mode = _required(payload, "mode")
    if mode not in ("keyGen", "encapDecap"):
        raise _error(FrameworkErrorCode.UNSUPPORTED_MODE, "unsupported ML-KEM mode")
    revision = _required(payload, "revision")
    if revision != "FIPS203":
        raise _error(FrameworkErrorCode.INVALID_FIELD, "unsupported ML-KEM revision")
    vs_id = _required(payload, "vsId")
    raw_groups = _required(payload, "testGroups")
    if not isinstance(vs_id, int) or not isinstance(raw_groups, list):
        raise _error(FrameworkErrorCode.INVALID_FIELD, "vsId/testGroups has invalid type")

    groups = []
    for raw_group in raw_groups:
        if not isinstance(raw_group, dict):
            raise _error(FrameworkErrorCode.INVALID_FIELD, "test group must be an object")
        tg_id = _required(raw_group, "tgId")
        if not isinstance(tg_id, int):
            raise _error(FrameworkErrorCode.INVALID_FIELD, "tgId must be an integer")
        _reject_unknown(
            raw_group,
            {"dk", "ek", "function", "parameterSet", "testType", "tests", "tgId"},
            context="test group",
            tg_id=tg_id,
        )
        try:
            parameter_set = MLKEMParameterSet.parse(_required(raw_group, "parameterSet", tg_id=tg_id))
        except MLKEMError as exc:
            raise _error(FrameworkErrorCode.INVALID_FIELD, "invalid parameterSet", tg_id=tg_id) from exc
        test_type = _required(raw_group, "testType", tg_id=tg_id)
        function = raw_group.get("function", "keyGen" if mode == "keyGen" else None)
        allowed = {"keyGen"} if mode == "keyGen" else {
            "encapsulation", "decapsulation", "encapsulationKeyCheck", "decapsulationKeyCheck"
        }
        if function not in allowed:
            raise _error(FrameworkErrorCode.UNSUPPORTED_FUNCTION, "unsupported ML-KEM function", tg_id=tg_id)
        raw_tests = _required(raw_group, "tests", tg_id=tg_id)
        if not isinstance(test_type, str) or not isinstance(raw_tests, list):
            raise _error(FrameworkErrorCode.INVALID_FIELD, "testType/tests has invalid type", tg_id=tg_id)
        tests = []
        test_fields = {
            "keyGen": {"tcId", "d", "z"},
            "encapsulation": {"tcId", "ek", "m"},
            "decapsulation": {"tcId", "dk", "c"},
            "encapsulationKeyCheck": {"tcId", "ek"},
            "decapsulationKeyCheck": {"tcId", "dk"},
        }[function]
        for raw_test in raw_tests:
            if not isinstance(raw_test, dict) or not isinstance(raw_test.get("tcId"), int):
                raise _error(FrameworkErrorCode.INVALID_FIELD, "test case requires integer tcId", tg_id=tg_id)
            _reject_unknown(raw_test, test_fields, context="test case", tg_id=tg_id)
            tests.append(ACVPTestCase(raw_test["tcId"], raw_test))
        shared = {key: value for key, value in raw_group.items() if key in ("ek", "dk")}
        groups.append(MLKEMTestGroup(tg_id, parameter_set, test_type, function, shared, tuple(tests)))

    return MLKEMVectorSet(version, vs_id, algorithm, mode, revision, tuple(groups))
