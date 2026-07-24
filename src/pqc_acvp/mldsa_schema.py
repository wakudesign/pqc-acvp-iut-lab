"""Strict parsing for the declared pure/external ML-DSA ACVP subset."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .framework import FrameworkError, FrameworkErrorCode, StructuredError
from .mldsa import MLDSAError, MLDSAParameterSet


@dataclass(frozen=True)
class MLDSATestCase:
    tc_id: int
    values: Mapping[str, Any]


@dataclass(frozen=True)
class MLDSATestGroup:
    tg_id: int
    parameter_set: MLDSAParameterSet
    test_type: str
    mode: str
    deterministic: bool | None
    tests: tuple[MLDSATestCase, ...]


@dataclass(frozen=True)
class MLDSAVectorSet:
    version: Mapping[str, Any] | None
    vs_id: int
    algorithm: str
    mode: str
    revision: str
    groups: tuple[MLDSATestGroup, ...]


def _error(code: FrameworkErrorCode, message: str, *, tg_id: int | None = None) -> FrameworkError:
    return FrameworkError(StructuredError(code.value, "parse", message, tg_id=tg_id))


def _required(mapping: Mapping[str, Any], key: str, *, tg_id: int | None = None) -> Any:
    if key not in mapping:
        raise _error(FrameworkErrorCode.MISSING_FIELD, f"missing required field: {key}", tg_id=tg_id)
    return mapping[key]


def _reject_unknown(mapping: Mapping[str, Any], allowed: set[str], *, context: str, tg_id: int | None = None) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise _error(FrameworkErrorCode.UNKNOWN_FIELD, f"unknown {context} field: {unknown[0]}", tg_id=tg_id)


def parse_mldsa_document(text: str) -> MLDSAVectorSet:
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

    _reject_unknown(payload, {"algorithm", "isSample", "mode", "revision", "testGroups", "vsId"}, context="vector set")
    if _required(payload, "algorithm") != "ML-DSA":
        raise _error(FrameworkErrorCode.UNSUPPORTED_ALGORITHM, "only ML-DSA is supported")
    mode = _required(payload, "mode")
    if mode not in {"keyGen", "sigGen", "sigVer"}:
        raise _error(FrameworkErrorCode.UNSUPPORTED_MODE, "unsupported ML-DSA mode")
    revision = _required(payload, "revision")
    if revision != "FIPS204":
        raise _error(FrameworkErrorCode.INVALID_FIELD, "unsupported ML-DSA revision")
    vs_id = _required(payload, "vsId")
    raw_groups = _required(payload, "testGroups")
    if not isinstance(vs_id, int) or not isinstance(raw_groups, list):
        raise _error(FrameworkErrorCode.INVALID_FIELD, "vsId/testGroups has invalid type")

    groups = []
    group_fields = {
        "keyGen": {"tgId", "testType", "parameterSet", "tests"},
        "sigGen": {"tgId", "testType", "parameterSet", "deterministic", "signatureInterface", "preHash", "tests"},
        "sigVer": {"tgId", "testType", "parameterSet", "signatureInterface", "preHash", "tests"},
    }[mode]
    test_fields = {
        "keyGen": {"tcId", "seed"},
        "sigGen": {"tcId", "message", "sk", "context", "rnd"},
        "sigVer": {"tcId", "message", "pk", "context", "signature"},
    }[mode]
    for raw_group in raw_groups:
        if not isinstance(raw_group, dict):
            raise _error(FrameworkErrorCode.INVALID_FIELD, "test group must be an object")
        tg_id = _required(raw_group, "tgId")
        if not isinstance(tg_id, int):
            raise _error(FrameworkErrorCode.INVALID_FIELD, "tgId must be an integer")
        _reject_unknown(raw_group, group_fields, context="test group", tg_id=tg_id)
        try:
            parameter_set = MLDSAParameterSet.parse(_required(raw_group, "parameterSet", tg_id=tg_id))
        except MLDSAError as exc:
            raise _error(FrameworkErrorCode.INVALID_FIELD, "invalid parameterSet", tg_id=tg_id) from exc
        test_type = _required(raw_group, "testType", tg_id=tg_id)
        if not isinstance(test_type, str):
            raise _error(FrameworkErrorCode.INVALID_FIELD, "testType must be a string", tg_id=tg_id)
        deterministic = None
        if mode != "keyGen":
            if raw_group.get("signatureInterface") != "external":
                raise _error(FrameworkErrorCode.UNSUPPORTED_FUNCTION, "only the external signature interface is supported", tg_id=tg_id)
            if raw_group.get("preHash") != "pure":
                raise _error(FrameworkErrorCode.UNSUPPORTED_FUNCTION, "only pure ML-DSA is supported", tg_id=tg_id)
        if mode == "sigGen":
            deterministic = _required(raw_group, "deterministic", tg_id=tg_id)
            if not isinstance(deterministic, bool):
                raise _error(FrameworkErrorCode.INVALID_FIELD, "deterministic must be boolean", tg_id=tg_id)
        raw_tests = _required(raw_group, "tests", tg_id=tg_id)
        if not isinstance(raw_tests, list):
            raise _error(FrameworkErrorCode.INVALID_FIELD, "tests must be an array", tg_id=tg_id)
        tests = []
        for raw_test in raw_tests:
            if not isinstance(raw_test, dict) or not isinstance(raw_test.get("tcId"), int):
                raise _error(FrameworkErrorCode.INVALID_FIELD, "test case requires integer tcId", tg_id=tg_id)
            _reject_unknown(raw_test, test_fields, context="test case", tg_id=tg_id)
            tests.append(MLDSATestCase(raw_test["tcId"], raw_test))
        groups.append(MLDSATestGroup(tg_id, parameter_set, test_type, mode, deterministic, tuple(tests)))

    return MLDSAVectorSet(version, vs_id, "ML-DSA", mode, revision, tuple(groups))
