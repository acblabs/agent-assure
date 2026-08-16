from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_assure.artifact_io import write_text_atomic
from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.schema.graph import AssuranceEvidenceGraph
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)


def evidence_graph_json_text(graph: AssuranceEvidenceGraph) -> str:
    payload = graph.model_dump(mode="json")
    AssuranceEvidenceGraph.model_validate(payload)
    validate_loaded_artifact_payload(payload, "assurance-evidence-graph")
    if redact_packet_payload(payload) != payload:
        raise ValueError("assurance evidence graph must be privacy-filtered before persistence")
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if len(rendered.encode("utf-8")) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError("assurance evidence graph exceeds the artifact JSON byte limit")
    return rendered


def evidence_graph_file_sha256(graph: AssuranceEvidenceGraph) -> str:
    return hashlib.sha256(evidence_graph_json_text(graph).encode("utf-8")).hexdigest()


def write_evidence_graph(graph: AssuranceEvidenceGraph, path: Path) -> None:
    rendered = evidence_graph_json_text(graph)
    write_text_atomic(path, rendered)


def load_evidence_graph(path: Path) -> AssuranceEvidenceGraph:
    payload = load_validated_artifact_payload(
        path,
        "assurance-evidence-graph",
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="assurance evidence graph",
    )
    return project_validated_artifact_payload(
        payload,
        AssuranceEvidenceGraph,
        kind="assurance-evidence-graph",
    )
