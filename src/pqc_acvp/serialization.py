"""ACVP response construction, serialization, and file writing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

def response_object(vector_set: Any, groups: Sequence[Mapping[str, Any]]) -> Any:
    payload = {
        "vsId": vector_set.vs_id,
        "algorithm": vector_set.algorithm,
        "mode": vector_set.mode,
        "revision": vector_set.revision,
        "testGroups": list(groups),
    }
    return [dict(vector_set.version), payload] if vector_set.version is not None else payload


def serialize_response(document: Any) -> str:
    return json.dumps(document, indent=2) + "\n"


def write_response(path: Path, serialized: str) -> None:
    path.write_text(serialized, encoding="utf-8")
