"""Backend-neutral metadata, summaries, and structured framework errors."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


@dataclass(frozen=True)
class BackendMetadata:
    name: str
    version: str
    commit: str
    target: str
    compiler: str
    flags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "commit": self.commit,
            "target": self.target,
            "compiler": self.compiler,
            "flags": list(self.flags),
        }


class FrameworkErrorCode(str, Enum):
    INVALID_DOCUMENT = "invalidDocument"
    MISSING_FIELD = "missingField"
    UNKNOWN_FIELD = "unknownField"
    INVALID_FIELD = "invalidField"
    INVALID_HEX = "invalidHex"
    UNSUPPORTED_ALGORITHM = "unsupportedAlgorithm"
    UNSUPPORTED_MODE = "unsupportedMode"
    UNSUPPORTED_FUNCTION = "unsupportedFunction"
    BACKEND_ERROR = "backendError"


@dataclass(frozen=True)
class StructuredError:
    code: str
    stage: str
    message: str
    mode: str | None = None
    tg_id: int | None = None
    tc_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "stage": self.stage,
            "message": self.message,
        }
        if self.mode is not None:
            result["mode"] = self.mode
        if self.tg_id is not None:
            result["tgId"] = self.tg_id
        if self.tc_id is not None:
            result["tcId"] = self.tc_id
        return result


class FrameworkError(Exception):
    def __init__(self, error: StructuredError) -> None:
        super().__init__(error.message)
        self.error = error


@dataclass(frozen=True)
class VectorSetSummary:
    algorithm: str
    mode: str
    revision: str
    status: str
    groups_seen: int
    tests_seen: int
    tests_produced: int
    function_counts: Mapping[str, int]
    backend: BackendMetadata
    errors: tuple[StructuredError, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "mode": self.mode,
            "revision": self.revision,
            "status": self.status,
            "groupsSeen": self.groups_seen,
            "testsSeen": self.tests_seen,
            "testsProduced": self.tests_produced,
            "functionCounts": dict(self.function_counts),
            "backend": self.backend.to_dict(),
            "errors": [error.to_dict() for error in self.errors],
        }


@dataclass
class RunSummary:
    vector_sets: list[VectorSetSummary] = field(default_factory=list)

    def add(self, summary: VectorSetSummary) -> None:
        self.vector_sets.append(summary)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "passed" if self.vector_sets and all(v.status == "generated" for v in self.vector_sets) else "failed",
            "totalVectorSets": len(self.vector_sets),
            "totalTestsSeen": sum(v.tests_seen for v in self.vector_sets),
            "totalTestsProduced": sum(v.tests_produced for v in self.vector_sets),
            "vectorSets": [vector.to_dict() for vector in self.vector_sets],
        }
