from __future__ import annotations

from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket


def test_evidence_packet_schema_exists() -> None:
    packet = EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id="packet-001",
        evaluation=EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="runset-001",
            state=GateState.not_evaluated,
        ),
        comparison=ComparisonSummary(
            artifact_kind="comparison-summary",
            baseline_runset_id="baseline",
            candidate_runset_id="candidate",
            classification=ComparisonClassification.provenance_only_change,
        ),
        limitations=("packet generation is reserved for a future release",),
    )
    assert packet.schema_version == "0.1.0"
