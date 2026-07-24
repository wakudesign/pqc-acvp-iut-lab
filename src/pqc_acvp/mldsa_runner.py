"""Credential-free orchestration for one ML-DSA vector-set document."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .framework import BackendMetadata, FrameworkError, VectorSetSummary
from .mldsa import MLDSAACVPTestBackend
from .mldsa_executor import execute_mldsa_vector_set
from .mldsa_schema import parse_mldsa_document
from .serialization import response_object, serialize_response, write_response


@dataclass(frozen=True)
class MLDSAVectorRunResult:
    serialized_response: str | None
    summary: VectorSetSummary


def run_mldsa_text(text: str, backend: MLDSAACVPTestBackend, metadata: BackendMetadata) -> MLDSAVectorRunResult:
    vector_set = parse_mldsa_document(text)
    try:
        execution = execute_mldsa_vector_set(backend, metadata, vector_set)
    except FrameworkError as exc:
        counts = Counter(group.mode for group in vector_set.groups for _ in group.tests)
        summary = VectorSetSummary(
            vector_set.algorithm, vector_set.mode, vector_set.revision, "failed",
            len(vector_set.groups), sum(len(group.tests) for group in vector_set.groups), 0,
            dict(counts), metadata, (exc.error,),
        )
        return MLDSAVectorRunResult(None, summary)
    document = response_object(vector_set, execution.response_groups)
    return MLDSAVectorRunResult(serialize_response(document), execution.summary)


def run_mldsa_file(request_path: Path, response_path: Path, backend: MLDSAACVPTestBackend, metadata: BackendMetadata) -> VectorSetSummary:
    result = run_mldsa_text(request_path.read_text(encoding="utf-8"), backend, metadata)
    if result.serialized_response is not None:
        write_response(response_path, result.serialized_response)
    return result.summary
