from __future__ import annotations

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

_VALIDATED_DIGEST = "a" * 64
_VALIDATED_GRAPH_NODE_ID = f"subject:{_VALIDATED_DIGEST}"


def _privacy_review_projection(
    value: object,
    *,
    field_name: str | None = None,
) -> object:
    """Exclude schema-validated cryptographic material from content detection.

    Hex digests and graph node IDs can contain chance digit sequences that look
    like payment-card numbers.  The graph schema validates those fields before
    this projection runs, so they cannot carry arbitrary text.  All other graph
    strings remain subject to the normal packet privacy detectors.
    """

    if field_name is not None and field_name.endswith("_digest"):
        return _VALIDATED_DIGEST
    if field_name == "node_id" or (field_name is not None and field_name.endswith("_node_id")):
        return _VALIDATED_GRAPH_NODE_ID
    if isinstance(value, dict):
        projected: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("assurance evidence graph keys must be strings")
            projected[key] = _privacy_review_projection(item, field_name=key)
        return projected
    if isinstance(value, list):
        return [_privacy_review_projection(item) for item in value]
    return value


def evidence_graph_json_text(graph: AssuranceEvidenceGraph) -> str:
    payload = graph.model_dump(mode="json")
    validate_loaded_artifact_payload(payload, "assurance-evidence-graph")
    privacy_review = _privacy_review_projection(payload)
    if redact_packet_payload(privacy_review) != privacy_review:
        raise ValueError("assurance evidence graph must be privacy-filtered before persistence")
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if len(rendered.encode("utf-8")) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError("assurance evidence graph exceeds the artifact JSON byte limit")
    return rendered


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
