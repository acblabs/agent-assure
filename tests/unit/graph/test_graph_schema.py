from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import agent_assure.schema.graph as graph_schema
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.graph.builder import (
    DEFAULT_GRAPH_LIMITATIONS,
    build_evidence_graph,
    legacy_packet_compatibility_manifest,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.efficacy import (
    INDEPENDENCE_CLASS_ORDER,
    ControlEfficacyGateReason,
)
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.graph import (
    GRAPH_CONTRACT_ID,
    LEGACY_PACKET_FIELD_PATHS,
    LEGACY_PACKET_SCHEMA_VERSIONS,
    MAX_GRAPH_REFERENCES,
    AssuranceEvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphEdgeKind,
    EvidenceGraphEvidenceIdentityProjection,
    EvidenceGraphEvidencePayload,
    EvidenceGraphEvidenceType,
    EvidenceGraphFieldCompatibility,
    EvidenceGraphFindingPayload,
    EvidenceGraphFindingType,
    EvidenceGraphNode,
    EvidenceGraphNodeKind,
    EvidenceGraphProjectionDisposition,
    EvidenceGraphReference,
    EvidenceGraphReferenceRole,
    EvidenceGraphRequirementPayload,
    EvidenceGraphRequirementType,
    EvidenceGraphSubjectPayload,
    _index_efficacy_outcomes,
    calculate_evidence_graph_digest,
)
from agent_assure.schema.mutation import EvidenceState, GateEffect, MutationResultState


def _failing_evaluation(*, message: str = "Material evidence is missing.") -> EvaluationSummary:
    return EvaluationSummary(
        runset_id="graph-schema-candidate",
        runset_digest="a" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(
            Finding(
                finding_id="finding-material-evidence",
                case_id="case-material-evidence",
                control_id="material_claims_have_evidence",
                target="claim:material",
                state=GateState.fail,
                reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                message=message,
            ),
        ),
    )


def _sample_graph() -> AssuranceEvidenceGraph:
    return build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="graph-schema-candidate",
            subject_digest="a" * 64,
        ),
        evaluation=_failing_evaluation(),
        limitations=("Only synthetic evidence was evaluated.",),
    )


def _reverse_object_keys(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _reverse_object_keys(item) for key, item in reversed(tuple(value.items()))}
    if isinstance(value, list):
        return [_reverse_object_keys(item) for item in value]
    return value


def _rehash(payload: dict[str, Any]) -> None:
    projection = {key: value for key, value in payload.items() if key != "graph_digest"}
    # Deliberately forge a digest for structurally invalid persisted input. The
    # public graph helper rejects invalid projections before hashing them.
    payload["graph_digest"] = sha256_hexdigest(projection)


def _endpoint_node_id(kind: str, label: str) -> str:
    return f"{kind}:{sha256_hexdigest({'label': label})}"


def _endpoint_nodes(
    kind: EvidenceGraphEdgeKind,
    source: str,
) -> dict[str, EvidenceGraphNode]:
    semantic_source = source in {"evidence", "finding"}
    if kind is EvidenceGraphEdgeKind.supports and semantic_source:
        evidence_state = EvidenceState.supported
        finding_state = EvidenceState.supported
        verdict_bearing = True
        outcome_reason = "MUTATION_CAUGHT"
    elif kind is EvidenceGraphEdgeKind.contradicts and semantic_source:
        evidence_state = EvidenceState.contradicted
        finding_state = EvidenceState.contradicted
        verdict_bearing = True
        outcome_reason = "MUTATION_SURVIVED"
    else:
        evidence_state = EvidenceState.out_of_scope
        finding_state = EvidenceState.out_of_scope
        verdict_bearing = False
        outcome_reason = "MUTATION_INAPPLICABLE"
    subject = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.subject,
        payload=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="candidate",
            subject_digest="a" * 64,
        ),
    )
    baseline = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.subject,
        payload=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="baseline",
        ),
    )
    requirement = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.requirement,
        payload=EvidenceGraphRequirementPayload(
            requirement_type=EvidenceGraphRequirementType.declared_expectations,
            requirement_id="declared-expectations",
        ),
        subject_node_id=subject.node_id,
    )
    evidence = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.evidence,
        payload=EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.mutation_result,
            source_artifact_kind="assurance-mutation-result",
            source_id="candidate",
            source_digest="b" * 64,
            state=evidence_state,
            verdict_bearing=verdict_bearing,
            evaluation_basis="deterministic",
        ),
        subject_node_id=subject.node_id,
    )
    finding = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.finding,
        payload=EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.mutation_result,
            source_artifact_kind="assurance-mutation-result",
            source_id="mutation-outcome",
            source_path="/state",
            state=finding_state,
            verdict_bearing=verdict_bearing,
            reason_codes=(outcome_reason,),
        ),
        subject_node_id=subject.node_id,
        parent_evidence_node_id=evidence.node_id,
    )
    return {
        "subject": subject,
        "baseline": baseline,
        "requirement": requirement,
        "evidence": evidence,
        "finding": finding,
    }


def _graph_with_edge(
    kind: EvidenceGraphEdgeKind,
    source: str,
    target: str,
) -> AssuranceEvidenceGraph:
    nodes = _endpoint_nodes(kind, source)
    base_edges = (
        EvidenceGraphEdge(
            kind=EvidenceGraphEdgeKind.derived_from,
            source_node_id=nodes["finding"].node_id,
            target_node_id=nodes["evidence"].node_id,
        ),
        *(
            EvidenceGraphEdge(
                kind=EvidenceGraphEdgeKind.scoped_to,
                source_node_id=nodes[node_kind].node_id,
                target_node_id=nodes["subject"].node_id,
            )
            for node_kind in ("requirement", "evidence", "finding")
        ),
    )
    tested_edge = EvidenceGraphEdge(
        kind=kind,
        source_node_id=nodes[source].node_id,
        target_node_id=nodes[target].node_id,
    )
    return AssuranceEvidenceGraph.from_parts(
        primary_subject_node_id=nodes["subject"].node_id,
        nodes=tuple(nodes.values()),
        edges=base_edges if tested_edge in base_edges else (*base_edges, tested_edge),
        compatibility=legacy_packet_compatibility_manifest(),
        limitations=("Synthetic endpoint-shape fixture.",),
    )


def test_contract_exposes_only_the_closed_four_node_and_six_edge_vocabularies() -> None:
    assert GRAPH_CONTRACT_ID == "AssuranceEvidenceGraph/v1"
    assert tuple(kind.value for kind in EvidenceGraphNodeKind) == (
        "subject",
        "requirement",
        "evidence",
        "finding",
    )
    assert tuple(kind.value for kind in EvidenceGraphEdgeKind) == (
        "supports",
        "contradicts",
        "targets",
        "derived_from",
        "depends_on",
        "scoped_to",
    )

    with pytest.raises(ValidationError):
        EvidenceGraphEdge(
            kind="relates_to",  # type: ignore[arg-type]
            source_node_id=_endpoint_node_id("finding", "a"),
            target_node_id=_endpoint_node_id("requirement", "a"),
        )


def test_graph_source_identifiers_cannot_be_empty() -> None:
    with pytest.raises(ValidationError, match="at least 1 character"):
        EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="",
        )


def test_rfc8785_digest_is_invariant_to_recursive_object_key_order() -> None:
    graph = _sample_graph()
    projection = graph.model_dump(mode="json", exclude={"graph_digest"})
    reordered = _reverse_object_keys(deepcopy(projection))

    assert isinstance(reordered, Mapping)
    assert calculate_evidence_graph_digest(projection) == graph.graph_digest
    assert calculate_evidence_graph_digest(reordered) == graph.graph_digest
    assert calculate_evidence_graph_digest(graph) == graph.graph_digest


def test_graph_constructor_canonicalizes_node_and_edge_set_order() -> None:
    graph = _sample_graph()

    rebuilt = AssuranceEvidenceGraph.from_parts(
        primary_subject_node_id=graph.primary_subject_node_id,
        nodes=tuple(reversed(graph.nodes)),
        edges=tuple(reversed(graph.edges)),
        compatibility=graph.compatibility,
        limitations=tuple(reversed(graph.limitations)),
    )

    assert rebuilt == graph
    assert rebuilt.graph_digest == graph.graph_digest


def test_persisted_graph_rejects_noncanonical_set_order_even_with_matching_digest() -> None:
    payload = _sample_graph().model_dump(mode="json")
    nodes = payload["nodes"]
    assert isinstance(nodes, list)
    payload["nodes"] = list(reversed(nodes))
    _rehash(payload)

    with pytest.raises(ValidationError, match="canonical kind-and-ID ordering"):
        AssuranceEvidenceGraph.model_validate(payload)


def test_graph_round_trips_through_plain_json_with_identical_digest() -> None:
    graph = _sample_graph()
    plain_json = json.loads(graph.model_dump_json())

    restored = AssuranceEvidenceGraph.model_validate(plain_json)

    assert restored == graph
    assert restored.graph_digest == graph.graph_digest
    assert restored.model_dump(mode="json") == graph.model_dump(mode="json")


def test_graph_rejects_duplicate_node_ids_and_duplicate_edges() -> None:
    graph = _sample_graph()

    with pytest.raises(ValidationError, match="node IDs must be unique"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=graph.primary_subject_node_id,
            nodes=(*graph.nodes, graph.nodes[0]),
            edges=graph.edges,
            compatibility=graph.compatibility,
            limitations=graph.limitations,
        )

    with pytest.raises(ValidationError, match="graph edges must be unique"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=graph.primary_subject_node_id,
            nodes=graph.nodes,
            edges=(*graph.edges, graph.edges[0]),
            compatibility=graph.compatibility,
            limitations=graph.limitations,
        )


def test_graph_node_ids_require_the_canonical_typed_identity_projection() -> None:
    payload = EvidenceGraphSubjectPayload(
        subject_type="run_set",
        subject_id="candidate",
    )
    node = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.subject,
        payload=payload,
    )
    persisted = node.model_dump(mode="json")

    with pytest.raises(ValidationError):
        EvidenceGraphNode.model_validate({**persisted, "node_id": "subject:primary"})
    with pytest.raises(ValidationError, match="canonical identity projection"):
        EvidenceGraphNode.model_validate({**persisted, "node_id": f"subject:{'1' * 64}"})
    forged_identity = deepcopy(persisted)
    forged_identity["identity"]["subject_id"] = "different-subject"
    with pytest.raises(ValidationError, match="canonical identity projection"):
        EvidenceGraphNode.model_validate(forged_identity)


def test_graph_rejects_unprovenanced_findings_and_incoherent_semantic_edges() -> None:
    graph = _sample_graph()
    finding = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.evaluation
    )
    derived_edge = next(
        edge
        for edge in graph.edges
        if edge.kind is EvidenceGraphEdgeKind.derived_from
        and edge.source_node_id == finding.node_id
    )
    with pytest.raises(ValidationError, match="exactly one source evidence"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=graph.primary_subject_node_id,
            nodes=graph.nodes,
            edges=tuple(edge for edge in graph.edges if edge != derived_edge),
            compatibility=graph.compatibility,
            limitations=graph.limitations,
        )

    target = next(
        edge.target_node_id
        for edge in graph.edges
        if edge.kind is EvidenceGraphEdgeKind.targets and edge.source_node_id == finding.node_id
    )
    forged_support = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.supports,
        source_node_id=finding.node_id,
        target_node_id=target,
    )
    with pytest.raises(ValidationError, match="contradicts its source state"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=graph.primary_subject_node_id,
            nodes=graph.nodes,
            edges=(*graph.edges, forged_support),
            compatibility=graph.compatibility,
            limitations=graph.limitations,
        )


def test_graph_rejects_dangling_edges_and_non_subject_primary_node() -> None:
    graph = _sample_graph()
    dangling = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.targets,
        source_node_id=next(
            node.node_id for node in graph.nodes if node.kind is EvidenceGraphNodeKind.finding
        ),
        target_node_id=_endpoint_node_id("requirement", "missing"),
    )

    with pytest.raises(ValidationError, match="cannot reference missing nodes"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=graph.primary_subject_node_id,
            nodes=graph.nodes,
            edges=(*graph.edges, dangling),
            compatibility=graph.compatibility,
            limitations=graph.limitations,
        )

    non_subject = next(
        node.node_id for node in graph.nodes if node.kind is EvidenceGraphNodeKind.evidence
    )
    with pytest.raises(ValidationError, match="must reference a present subject node"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=non_subject,
            nodes=graph.nodes,
            edges=graph.edges,
            compatibility=graph.compatibility,
            limitations=graph.limitations,
        )


@pytest.mark.parametrize(
    ("kind", "source", "target"),
    (
        (EvidenceGraphEdgeKind.supports, "evidence", "requirement"),
        (EvidenceGraphEdgeKind.supports, "finding", "requirement"),
        (EvidenceGraphEdgeKind.contradicts, "evidence", "requirement"),
        (EvidenceGraphEdgeKind.contradicts, "finding", "requirement"),
        (EvidenceGraphEdgeKind.targets, "finding", "requirement"),
        (EvidenceGraphEdgeKind.derived_from, "finding", "evidence"),
        (EvidenceGraphEdgeKind.scoped_to, "requirement", "subject"),
        (EvidenceGraphEdgeKind.scoped_to, "evidence", "subject"),
        (EvidenceGraphEdgeKind.scoped_to, "finding", "subject"),
    ),
)
def test_edge_endpoint_matrix_accepts_only_declared_shapes(
    kind: EvidenceGraphEdgeKind,
    source: str,
    target: str,
) -> None:
    graph = _graph_with_edge(kind, source, target)

    expected_count = (
        4
        if kind
        in {
            EvidenceGraphEdgeKind.derived_from,
            EvidenceGraphEdgeKind.scoped_to,
        }
        else 5
    )
    assert len(graph.edges) == expected_count


@pytest.mark.parametrize(
    ("kind", "source", "target"),
    (
        (EvidenceGraphEdgeKind.supports, "subject", "requirement"),
        (EvidenceGraphEdgeKind.contradicts, "requirement", "evidence"),
        (EvidenceGraphEdgeKind.targets, "evidence", "requirement"),
        (EvidenceGraphEdgeKind.derived_from, "evidence", "finding"),
        (EvidenceGraphEdgeKind.depends_on, "finding", "evidence"),
        (EvidenceGraphEdgeKind.depends_on, "evidence", "requirement"),
        (EvidenceGraphEdgeKind.scoped_to, "requirement", "evidence"),
    ),
)
def test_edge_endpoint_matrix_rejects_undeclared_shapes(
    kind: EvidenceGraphEdgeKind,
    source: str,
    target: str,
) -> None:
    with pytest.raises(ValidationError, match="invalid endpoint kinds"):
        _graph_with_edge(kind, source, target)


def test_edges_reject_self_reference_before_graph_construction() -> None:
    with pytest.raises(ValidationError, match="cannot be self-referential"):
        node_id = _endpoint_node_id("subject", "primary")
        EvidenceGraphEdge(
            kind=EvidenceGraphEdgeKind.scoped_to,
            source_node_id=node_id,
            target_node_id=node_id,
        )


def test_non_subject_nodes_require_exactly_one_subject_scope() -> None:
    nodes = _endpoint_nodes(EvidenceGraphEdgeKind.supports, "evidence")
    edges = (
        EvidenceGraphEdge(
            kind=EvidenceGraphEdgeKind.derived_from,
            source_node_id=nodes["finding"].node_id,
            target_node_id=nodes["evidence"].node_id,
        ),
        *(
            EvidenceGraphEdge(
                kind=EvidenceGraphEdgeKind.scoped_to,
                source_node_id=nodes[node_kind].node_id,
                target_node_id=nodes["subject"].node_id,
            )
            for node_kind in ("requirement", "evidence", "finding")
        ),
        EvidenceGraphEdge(
            kind=EvidenceGraphEdgeKind.scoped_to,
            source_node_id=nodes["requirement"].node_id,
            target_node_id=nodes["baseline"].node_id,
        ),
    )

    with pytest.raises(ValidationError, match="exactly one subject scope"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=nodes["subject"].node_id,
            nodes=tuple(nodes.values()),
            edges=edges,
            compatibility=legacy_packet_compatibility_manifest(),
            limitations=("Synthetic subject-scope fixture.",),
        )


def test_relationship_edges_cannot_cross_subject_scopes() -> None:
    nodes = _endpoint_nodes(EvidenceGraphEdgeKind.supports, "evidence")
    requirement_payload = nodes["requirement"].payload
    assert isinstance(requirement_payload, EvidenceGraphRequirementPayload)
    nodes["requirement"] = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.requirement,
        payload=requirement_payload,
        subject_node_id=nodes["baseline"].node_id,
    )
    edges = (
        EvidenceGraphEdge(
            kind=EvidenceGraphEdgeKind.derived_from,
            source_node_id=nodes["finding"].node_id,
            target_node_id=nodes["evidence"].node_id,
        ),
        EvidenceGraphEdge(
            kind=EvidenceGraphEdgeKind.supports,
            source_node_id=nodes["evidence"].node_id,
            target_node_id=nodes["requirement"].node_id,
        ),
        EvidenceGraphEdge(
            kind=EvidenceGraphEdgeKind.scoped_to,
            source_node_id=nodes["requirement"].node_id,
            target_node_id=nodes["baseline"].node_id,
        ),
        *(
            EvidenceGraphEdge(
                kind=EvidenceGraphEdgeKind.scoped_to,
                source_node_id=nodes[node_kind].node_id,
                target_node_id=nodes["subject"].node_id,
            )
            for node_kind in ("evidence", "finding")
        ),
    )

    with pytest.raises(ValidationError, match="cannot cross subject scopes"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=nodes["subject"].node_id,
            nodes=tuple(nodes.values()),
            edges=edges,
            compatibility=legacy_packet_compatibility_manifest(),
            limitations=("Synthetic cross-subject fixture.",),
        )


def test_invalid_graph_and_payload_digests_fail_closed() -> None:
    graph = _sample_graph()
    invalid_syntax = graph.model_dump(mode="json")
    invalid_syntax["graph_digest"] = "not-a-sha256"
    with pytest.raises(ValidationError):
        AssuranceEvidenceGraph.model_validate(invalid_syntax)

    incorrect = graph.model_dump(mode="json")
    incorrect["graph_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="does not match the canonical artifact projection"):
        AssuranceEvidenceGraph.model_validate(incorrect)

    node_payload = graph.nodes[-1].model_dump(mode="json")
    node_payload["payload_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="does not match its canonical payload"):
        EvidenceGraphNode.model_validate(node_payload)

    with pytest.raises(ValueError, match="must exclude graph_digest"):
        calculate_evidence_graph_digest(graph.model_dump(mode="json"))


def test_digest_projection_rejects_nonfinite_numbers() -> None:
    projection = _sample_graph().model_dump(mode="json", exclude={"graph_digest"})
    nodes = projection["nodes"]
    assert isinstance(nodes, list)
    subject = nodes[0]
    assert isinstance(subject, dict)
    payload = subject["payload"]
    assert isinstance(payload, dict)
    payload["subject_id"] = float("inf")

    with pytest.raises(ValueError):
        calculate_evidence_graph_digest(projection)


def test_digest_projection_rejects_arbitrary_and_recursive_mappings() -> None:
    with pytest.raises(ValueError):
        calculate_evidence_graph_digest({})

    recursive: dict[str, object] = {}
    recursive["recursive"] = recursive
    with pytest.raises(ValueError):
        calculate_evidence_graph_digest(recursive)

    graph = _sample_graph()
    noncanonical_instance = graph.model_copy(update={"nodes": tuple(reversed(graph.nodes))})
    with pytest.raises(ValueError, match="canonical kind-and-ID ordering"):
        calculate_evidence_graph_digest(noncanonical_instance)


def test_legacy_packet_compatibility_manifest_is_complete_and_explicit() -> None:
    manifest = legacy_packet_compatibility_manifest()
    project_root = Path(__file__).resolve().parents[3]
    frozen_fields: set[str] = set()
    for version in ("0.5.0", "0.6.0", "0.6.1", "0.6.2"):
        schema_path = project_root / "schemas" / f"v{version}" / "evidence-packet.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        frozen_fields.update(schema["properties"])
    frozen_paths = tuple(f"/{field}" for field in sorted(frozen_fields))

    assert manifest.projection_scope == "decision_fields"
    assert manifest.source_schema_versions == LEGACY_PACKET_SCHEMA_VERSIONS
    assert tuple(field.source_path for field in manifest.fields) == frozen_paths
    assert LEGACY_PACKET_FIELD_PATHS == frozen_paths
    assert len({field.source_path for field in manifest.fields}) == len(manifest.fields)
    assert all(
        field.disposition is EvidenceGraphProjectionDisposition.represented
        for field in manifest.fields
        if field.verdict_bearing
    )
    assert all(
        field.reason_code is not None and not field.target_node_kinds
        for field in manifest.fields
        if field.disposition is EvidenceGraphProjectionDisposition.unsupported
    )

    represented_paths = {
        field.source_path
        for field in manifest.fields
        if field.disposition is EvidenceGraphProjectionDisposition.represented
    }
    assert represented_paths == {
        "/comparison",
        "/control_efficacy",
        "/control_efficacy_gate",
        "/control_efficacy_gate_profile",
        "/evaluation",
        "/limitations",
    }


def test_compatibility_manifest_rejects_unsupported_verdict_fields_and_gaps() -> None:
    with pytest.raises(ValidationError, match="verdict-bearing.*cannot be unsupported"):
        EvidenceGraphFieldCompatibility(
            source_path="/verdict",
            verdict_bearing=True,
            disposition=EvidenceGraphProjectionDisposition.unsupported,
            reason_code="projection-unavailable",
        )

    manifest = legacy_packet_compatibility_manifest()
    with pytest.raises(ValidationError, match="complete and sorted"):
        type(manifest)(fields=tuple(reversed(manifest.fields)))


def test_default_graph_limitations_are_stable_and_nonempty() -> None:
    graph = _sample_graph()

    assert graph.limitations == tuple(sorted(DEFAULT_GRAPH_LIMITATIONS))
    assert all(limitation.strip() for limitation in graph.limitations)


def test_finding_subtype_fields_fail_closed_outside_their_exact_types() -> None:
    common = {
        "source_artifact_kind": "finding",
        "source_id": "finding-one",
        "source_path": "/findings/0",
        "state": EvidenceState.inconclusive,
        "verdict_bearing": True,
    }
    with pytest.raises(ValidationError, match="gate_effect belongs exactly"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.evaluation,
            gate_effect=GateEffect.review,
            **common,
        )
    with pytest.raises(ValidationError, match="required belongs exactly"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.evaluation,
            required=False,
            **common,
        )
    with pytest.raises(ValidationError, match="critical and independently_challenged"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.evaluation,
            critical=False,
            independently_challenged=False,
            **common,
        )
    with pytest.raises(ValidationError, match="gate_effect belongs exactly"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.control_efficacy_gate,
            **common,
        )


def test_gate_finding_reference_capacity_includes_profile_and_full_threat_catalog() -> None:
    references = (
        EvidenceGraphReference(
            role=EvidenceGraphReferenceRole.gate_profile,
            value="strict-profile",
        ),
        *(
            EvidenceGraphReference(
                role=EvidenceGraphReferenceRole.threat,
                value=f"threat-{index:04d}",
            )
            for index in range(MAX_GRAPH_REFERENCES - 1)
        ),
    )

    finding = EvidenceGraphFindingPayload(
        finding_type=EvidenceGraphFindingType.control_efficacy_gate,
        source_artifact_kind="control-efficacy-gate-decision",
        source_id="critical-threats-uncovered",
        source_path="/findings/0",
        state=EvidenceState.violated,
        verdict_bearing=True,
        reason_codes=(ControlEfficacyGateReason.critical_threat_uncovered.value,),
        gate_effect=GateEffect.block,
        references=references,
    )

    assert len(finding.references) == MAX_GRAPH_REFERENCES


def test_projection_reason_codes_are_exact_for_limitation_mutation_and_threat() -> None:
    common = {
        "source_artifact_kind": "assurance-mutation-result",
        "source_id": "mutation-outcome",
        "source_path": "/state",
        "state": EvidenceState.supported,
        "verdict_bearing": True,
    }
    with pytest.raises(ValidationError, match="mutation outcome reason"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.mutation_result,
            reason_codes=("MUTATION_TOTALLY_MADE_UP",),
            **common,
        )
    with pytest.raises(ValidationError, match="limitation finding requires"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.limitation,
            reason_codes=("TOTALLY_MADE_UP",),
            state=EvidenceState.inconclusive,
            verdict_bearing=False,
            source_artifact_kind="evidence-packet",
            source_id="limitation-0",
            source_path="/limitations/0",
        )
    with pytest.raises(ValidationError, match="threat reason must match"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.control_efficacy_threat,
            reason_codes=("TOTALLY_MADE_UP",),
            references=(
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.applicability,
                    value="applicable",
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.operator,
                    value="challenger",
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.threat,
                    value="threat-one",
                ),
            ),
            critical=False,
            independently_challenged=False,
            source_artifact_kind="control-efficacy-report",
            source_id="threat-one",
            source_path="/threat_coverage/0",
            state=EvidenceState.supported,
            verdict_bearing=True,
        )


def test_applicability_and_diagnostic_reference_roles_are_not_overloaded() -> None:
    with pytest.raises(ValidationError, match="applicability references are reserved"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.mutation_result,
            source_artifact_kind="assurance-mutation-result",
            source_id="mutation-outcome",
            source_path="/state",
            state=EvidenceState.supported,
            verdict_bearing=True,
            reason_codes=("MUTATION_CAUGHT",),
            references=(
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.applicability,
                    value="catalog_integrity_error",
                ),
            ),
        )
    with pytest.raises(ValidationError, match="diagnostic references belong only"):
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.evaluation,
            source_artifact_kind="finding",
            source_id="finding-one",
            source_path="/findings/0",
            state=EvidenceState.violated,
            verdict_bearing=True,
            references=(
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.diagnostic,
                    value="catalog_integrity_error",
                ),
            ),
        )


def test_non_deterministic_mutation_evidence_cannot_claim_a_verdict() -> None:
    with pytest.raises(ValidationError, match="mutation-result evidence state"):
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.mutation_result,
            source_artifact_kind="assurance-mutation-result",
            source_id="mutation-result",
            source_digest="b" * 64,
            state=EvidenceState.supported,
            verdict_bearing=True,
            evaluation_basis="stochastic",
        )


def test_evaluation_evidence_aggregate_must_match_its_findings() -> None:
    graph = _sample_graph()
    evidence = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.evaluation
    )
    assert isinstance(evidence.identity, EvidenceGraphEvidenceIdentityProjection)
    forged_payload = EvidenceGraphEvidencePayload.model_validate(
        {
            **evidence.payload.model_dump(mode="json"),
            "state": EvidenceState.supported.value,
            "verdict_bearing": True,
        }
    )
    forged = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.evidence,
        payload=forged_payload,
        subject_node_id=evidence.identity.subject_node_id,
    )

    with pytest.raises(ValidationError, match="aggregate findings"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=graph.primary_subject_node_id,
            nodes=tuple(
                forged if node.node_id == evidence.node_id else node for node in graph.nodes
            ),
            edges=tuple(
                edge
                for edge in graph.edges
                if not (
                    edge.source_node_id == evidence.node_id
                    and edge.kind
                    in {
                        EvidenceGraphEdgeKind.supports,
                        EvidenceGraphEdgeKind.contradicts,
                    }
                )
            ),
            compatibility=graph.compatibility,
            limitations=graph.limitations,
        )


def test_efficacy_outcome_indexes_scan_inputs_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CountingOutcomeMap(dict[str, EvidenceGraphFindingPayload]):
        item_scans = 0

        def items(self):  # type: ignore[override]
            self.item_scans += 1
            return super().items()

    outcomes = CountingOutcomeMap()
    states: dict[str, MutationResultState] = {}
    independence_class = INDEPENDENCE_CLASS_ORDER[0].value
    for index in range(256):
        operator_id = f"operator-{index:04d}"
        threat_id = f"threat-{index:04d}"
        outcomes[operator_id] = EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.control_efficacy_outcome,
            source_artifact_kind="control-efficacy-report",
            source_id=operator_id,
            source_path=f"/operator_outcomes/{index}",
            state=EvidenceState.supported,
            verdict_bearing=True,
            reason_codes=("MUTATION_CAUGHT",),
            references=(
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.applicability,
                    value="applicable",
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.control,
                    value="control-one",
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.independence_class,
                    value=independence_class,
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.invariant_family,
                    value="family-one",
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.operator,
                    value=operator_id,
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.present_control,
                    value="control-one",
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.scoped_threat,
                    value=threat_id,
                ),
                EvidenceGraphReference(
                    role=EvidenceGraphReferenceRole.threat,
                    value=threat_id,
                ),
            ),
            required=False,
        )
        states[operator_id] = MutationResultState.caught

    reference_scans = 0
    original_indexer = graph_schema._index_reference_values

    def counting_indexer(references: tuple[EvidenceGraphReference, ...]):
        nonlocal reference_scans
        reference_scans += 1
        return original_indexer(references)

    monkeypatch.setattr(graph_schema, "_index_reference_values", counting_indexer)
    (
        states_by_family,
        _,
        challengers_by_threat,
        _,
        _,
        _,
    ) = _index_efficacy_outcomes(outcomes, states)

    assert outcomes.item_scans == 1
    assert reference_scans == len(outcomes)
    assert len(states_by_family["family-one"]) == 256
    assert len(challengers_by_threat) == 256
