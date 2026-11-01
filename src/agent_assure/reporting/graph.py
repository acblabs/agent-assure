from __future__ import annotations

import json
from pathlib import Path

from agent_assure.artifact_io import write_text_atomic
from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES
from agent_assure.privacy.digest_fields import is_sha256_hex_digest
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.schema.graph import AssuranceEvidenceGraph
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)

_VALIDATED_DIGEST = "a" * 64
_VALIDATED_GRAPH_NODE_ID = f"subject:{_VALIDATED_DIGEST}"


def _has_mutation_result_digest_aliases(value: dict[str, object]) -> bool:
    identity = value.get("identity")
    payload = value.get("payload")
    if not isinstance(identity, dict) or not isinstance(payload, dict):
        return False
    source_id = payload.get("source_id")
    return (
        value.get("kind") == "evidence"
        and identity.get("identity_kind") == "evidence"
        and payload.get("payload_kind") == "evidence"
        and identity.get("evidence_type") == payload.get("evidence_type") == "mutation_result"
        and identity.get("source_artifact_kind")
        == payload.get("source_artifact_kind")
        == "assurance-mutation-result"
        and is_sha256_hex_digest(source_id)
        and source_id == payload.get("source_digest") == identity.get("source_id")
    )


def _privacy_review_value(
    value: object,
    *,
    field_name: str | None = None,
) -> object:
    """Exclude schema-validated cryptographic material from content detection.

    Hex digests and graph node IDs can contain chance digit sequences that look
    like payment-card numbers.  The graph schema validates named digest fields
    and node IDs before this projection runs.  Source-digest reference values
    are exempted only when they independently match the SHA-256 grammar.  All
    other graph strings remain subject to the normal packet privacy detectors.
    """

    if field_name is not None and field_name.endswith("_digest"):
        return _VALIDATED_DIGEST
    if field_name == "node_id" or (field_name is not None and field_name.endswith("_node_id")):
        return _VALIDATED_GRAPH_NODE_ID
    if isinstance(value, dict):
        if (
            set(value) == {"role", "value"}
            and value.get("role") == "source_digest"
            and is_sha256_hex_digest(value.get("value"))
        ):
            return {"role": "source_digest", "value": _VALIDATED_DIGEST}
        projected: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("assurance evidence graph keys must be strings")
            projected[key] = _privacy_review_value(item, field_name=key)
        return projected
    if isinstance(value, list):
        return [_privacy_review_value(item) for item in value]
    return value


def _privacy_review_projection(payload: dict[str, object]) -> dict[str, object]:
    """Mask digest aliases only on actual nodes of the fully validated graph."""

    projected = _privacy_review_value(payload)
    if not isinstance(projected, dict):
        raise TypeError("assurance evidence graph projection must be an object")
    nodes = payload.get("nodes")
    projected_nodes = projected.get("nodes")
    if not isinstance(nodes, list) or not isinstance(projected_nodes, list):
        raise TypeError("assurance evidence graph projection requires validated nodes")
    for node, projected_node in zip(nodes, projected_nodes, strict=True):
        if not isinstance(node, dict) or not isinstance(projected_node, dict):
            raise TypeError("assurance evidence graph nodes must be objects")
        if _has_mutation_result_digest_aliases(node):
            identity = projected_node.get("identity")
            evidence = projected_node.get("payload")
            if not isinstance(identity, dict) or not isinstance(evidence, dict):
                raise TypeError("mutation-result digest aliases require validated evidence")
            # These are newly allocated review dictionaries. The original graph,
            # including its source IDs and canonical digests, is serialized below.
            identity["source_id"] = _VALIDATED_DIGEST
            evidence["source_id"] = _VALIDATED_DIGEST
    return projected


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
