from __future__ import annotations

import unicodedata
from typing import cast

import pytest
from pydantic import ValidationError

from agent_assure.evaluation.expectations import CaseExpectation
from agent_assure.evaluation.invariants import evaluate_case
from agent_assure.policies.evidence import (
    claim_finding_target,
    evaluate_evidence_provenance_identity,
    evaluate_material_claim_evidence,
    evaluate_required_evidence,
    evidence_ref_finding_target,
)
from agent_assure.schema.base import SCHEMA_VERSION, SchemaVersion
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    EvidenceRef,
)
from agent_assure.schema.suite import SuiteCase

_CURRENT_SCHEMA_VERSION = cast(SchemaVersion, SCHEMA_VERSION)


def test_evidence_provenance_identity_accepts_one_shared_source() -> None:
    run = _run(
        evidence_refs=(_ref("ref-a", "source-a"),),
        evidence_items=(_item("ref-a", "source-a"),),
    )

    assert evaluate_evidence_provenance_identity(run) == ()


def test_run_record_rejects_conflicting_content_for_one_evidence_identity() -> None:
    first = _item("ref-a", "source-a")
    conflicting = first.model_copy(update={"content_digest": "e" * 64})

    with pytest.raises(ValidationError, match="must have one content_digest"):
        _run(
            evidence_refs=(_ref("ref-a", "source-a"),),
            evidence_items=(first, conflicting),
        )


def test_evidence_policy_defends_against_unchecked_conflicting_content() -> None:
    first = _item("ref-a", "source-a")
    valid = _run(
        evidence_refs=(_ref("ref-a", "source-a"),),
        evidence_items=(first,),
    )
    unchecked = valid.model_copy(
        update={
            "evidence_items": (
                first,
                first.model_copy(update={"content_digest": "e" * 64}),
            )
        }
    )

    findings = evaluate_evidence_provenance_identity(unchecked)

    assert len(findings) == 1
    assert findings[0].reason_code is ReasonCode.EVIDENCE_PROVENANCE_MISMATCH
    assert findings[0].state is GateState.fail


def test_evidence_provenance_identity_is_canonical_and_does_not_leak_sources() -> None:
    run = _run(
        evidence_refs=(
            _ref("ref-z", "private-ref-z"),
            _ref("ref-a", "private-ref-a"),
        ),
        evidence_items=(
            _item("ref-z", "private-item-z"),
            _item("ref-a", "private-item-a"),
        ),
    )

    findings = evaluate_evidence_provenance_identity(run)

    assert tuple(finding.target for finding in findings) == (
        evidence_ref_finding_target("ref-a"),
        evidence_ref_finding_target("ref-z"),
    )
    assert all(finding.control_id == "evidence_provenance_identity" for finding in findings)
    assert all(
        finding.reason_code is ReasonCode.EVIDENCE_PROVENANCE_MISMATCH for finding in findings
    )
    assert all(finding.state is GateState.fail for finding in findings)
    assert all(finding.severity is Severity.blocker for finding in findings)
    assert all("private-" not in finding.message for finding in findings)
    assert all("ref-" not in finding.target for finding in findings)


def test_evidence_provenance_identity_rejects_every_missing_side() -> None:
    run = _run(
        evidence_refs=(_ref("ref-only", "source-ref"),),
        evidence_items=(_item("item-only", "source-item"),),
    )

    findings = evaluate_evidence_provenance_identity(run)

    assert tuple(finding.target for finding in findings) == (
        evidence_ref_finding_target("item-only"),
        evidence_ref_finding_target("ref-only"),
    )
    assert all("item-only" not in finding.message for finding in findings)
    assert all("ref-only" not in finding.message for finding in findings)


def test_evidence_provenance_identity_rejects_legacy_blank_identifiers() -> None:
    run = _run(
        schema_version="0.6.0",
        evidence_refs=(EvidenceRef(schema_version="0.6.0", ref_id="", source_id=" \t"),),
        evidence_items=(
            EvidenceItem(
                schema_version="0.6.0",
                ref_id="",
                source_id=" \t",
                content_digest="d" * 64,
            ),
        ),
    )

    findings = evaluate_evidence_provenance_identity(run)

    assert len(findings) == 1
    assert findings[0].target == evidence_ref_finding_target("")
    assert findings[0].reason_code is ReasonCode.EVIDENCE_PROVENANCE_MISMATCH


def test_material_claim_requires_both_reference_and_content_item() -> None:
    expectation = Expectation(
        expectation_id="expect-material-evidence",
        case_id="case-evidence-provenance",
        material_claim_ids=("claim-a",),
    )
    link = ClaimEvidenceLink(claim_id="claim-a", evidence_ref_id="item-only")
    incomplete = _run(
        evidence_refs=(_ref("ref-only", "source-ref"),),
        evidence_items=(_item("item-only", "source-item"),),
        claim_evidence_links=(link,),
    )
    complete = _run(
        evidence_refs=(_ref("item-only", "source-item"),),
        evidence_items=(_item("item-only", "source-item"),),
        claim_evidence_links=(link,),
    )

    findings = evaluate_material_claim_evidence(incomplete, expectation)

    assert len(findings) == 1
    assert findings[0].target == claim_finding_target("claim-a")
    assert findings[0].reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
    assert evaluate_material_claim_evidence(complete, expectation) == ()


def test_evidence_findings_do_not_copy_hostile_expectation_identifiers() -> None:
    hostile_id = "e\x1b[2Kref\u202egnitrops"
    expectation = Expectation(
        schema_version="0.5.0",
        expectation_id="expect-hostile-evidence-identifiers",
        case_id="case-evidence-provenance",
        required_evidence_refs=(hostile_id,),
        material_claim_ids=(hostile_id,),
    )
    run = _run(evidence_refs=(), evidence_items=())

    required = evaluate_required_evidence(run, expectation)
    material = evaluate_material_claim_evidence(run, expectation)

    assert len(required) == 1
    assert required[0].target == evidence_ref_finding_target(hostile_id)
    assert required[0].message == "required evidence reference is missing"
    assert len(material) == 1
    assert material[0].target == claim_finding_target(hostile_id)
    assert material[0].message == (
        "fixture-declared material claim has no paired reference and "
        "content-addressed evidence item link"
    )
    assert claim_finding_target(hostile_id) != evidence_ref_finding_target(hostile_id)
    for finding in required + material:
        assert hostile_id not in finding.target
        assert hostile_id not in finding.message
        assert not any(
            unicodedata.category(character).startswith("C")
            for character in finding.target + finding.message
        )


def test_evaluate_case_invokes_evidence_provenance_identity_control() -> None:
    run = _run(
        evidence_refs=(_ref("ref-a", "source-ref"),),
        evidence_items=(_item("ref-a", "source-item"),),
    )
    case_expectation = CaseExpectation(
        case=SuiteCase(
            case_id=run.case_id,
            title="Evidence provenance identity",
            expectation_id="expect-evidence-provenance",
        ),
        expectation=Expectation(
            expectation_id="expect-evidence-provenance",
            case_id=run.case_id,
        ),
    )

    findings = tuple(
        finding
        for finding in evaluate_case(case_expectation, run)
        if finding.control_id == "evidence_provenance_identity"
    )

    assert len(findings) == 1
    assert findings[0].target == evidence_ref_finding_target("ref-a")


def _run(
    *,
    schema_version: SchemaVersion = _CURRENT_SCHEMA_VERSION,
    evidence_refs: tuple[EvidenceRef, ...],
    evidence_items: tuple[EvidenceItem, ...],
    claim_evidence_links: tuple[ClaimEvidenceLink, ...] = (),
) -> AgentRunRecord:
    return AgentRunRecord(
        schema_version=schema_version,
        run_id="run-evidence-provenance",
        case_id="case-evidence-provenance",
        pipeline_id="evidence.provenance.tests",
        recommendation="approve",
        outcome="approved",
        input_summary="synthetic input",
        output_summary="synthetic output",
        evidence_refs=evidence_refs,
        evidence_items=evidence_items,
        claim_evidence_links=claim_evidence_links,
    )


def _ref(ref_id: str, source_id: str) -> EvidenceRef:
    return EvidenceRef(ref_id=ref_id, source_id=source_id)


def _item(ref_id: str, source_id: str) -> EvidenceItem:
    return EvidenceItem(
        ref_id=ref_id,
        source_id=source_id,
        content_digest="d" * 64,
    )
