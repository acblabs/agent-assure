from __future__ import annotations

import pytest

from agent_assure.graph.builder import build_evidence_graph
from agent_assure.schema.graph import (
    EvidenceGraphSubjectPayload,
    calculate_evidence_graph_digest,
)


def test_graph_digest_rejects_cycle_in_otherwise_valid_graph_projection() -> None:
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="cyclic-graph-projection",
        )
    )
    projection = graph.model_dump(mode="json", exclude={"graph_digest"})
    node_payload = projection["nodes"][0]["payload"]
    node_payload["cycle"] = projection

    with pytest.raises(ValueError, match="cyclic reference"):
        calculate_evidence_graph_digest(projection)
