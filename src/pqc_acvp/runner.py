"""Credential-free orchestration for one local ACVP vector-set document."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .acvp_schema import parse_mlkem_document
from .framework import BackendMetadata, FrameworkError, StructuredError, VectorSetSummary
from .mlkem import MLKEMACVPTestBackend
from .mlkem_executor import execute_vector_set
from .serialization import response_object, serialize_response, write_response


@dataclass(frozen=True)
class VectorRunResult:
    serialized_response: str | None
    summary: VectorSetSummary


def run_text(text: str, backend: MLKEMACVPTestBackend, metadata: BackendMetadata) -> VectorRunResult:
    vector_set = parse_mlkem_document(text)
    try:
        execution = execute_vector_set(backend, metadata, vector_set)
    except FrameworkError as exc:
        counts = Counter(group.function for group in vector_set.groups for _ in group.tests)
        summary = VectorSetSummary(
            vector_set.algorithm, vector_set.mode, vector_set.revision, "failed",
            len(vector_set.groups), sum(len(g.tests) for g in vector_set.groups), 0,
            dict(counts), metadata, (exc.error,),
        )
        return VectorRunResult(None, summary)
    document = response_object(vector_set, execution.response_groups)
    return VectorRunResult(serialize_response(document), execution.summary)


def run_file(request_path: Path, response_path: Path, backend: MLKEMACVPTestBackend, metadata: BackendMetadata) -> VectorSetSummary:
    result = run_text(request_path.read_text(encoding="utf-8"), backend, metadata)
    if result.serialized_response is not None:
        write_response(response_path, result.serialized_response)
    return result.summary
