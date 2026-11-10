from __future__ import annotations

import copy
import json
import sys
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_s1_successor as successor  # noqa: E402

RESULT = "a" * 40
PARENT = "b" * 40
CLOSURE = "c" * 40
SCOPE = "sha256:" + "1" * 64
KICKOFF = "sha256:" + "2" * 64
TRUST = "sha256:" + "3" * 64
WORKFLOW = "sha256:" + "4" * 64
SOURCE = "sha256:" + "5" * 64
EXPIRY = "2026-11-20T00:00:00Z"
PREPARE_NOW = datetime(2026, 11, 7, 14, 0, tzinfo=UTC)
VERIFY_NOW = datetime(2026, 11, 7, 14, 20, tzinfo=UTC)


def moment(clock: str) -> str:
    return f"2026-11-07T{clock}:00Z"


@dataclass
class SyntheticTrustedBoundary:
    """Deliberately synthetic verified-source outcomes, not cryptographic tests.

    Tests exercise composition and substitution resistance with a trusted fake
    verifier. No production code defaults to this boundary or accepts JSON
    verification flags. Real OpenSSH and frozen-runtime coverage remains in
    the S1 governance suite and the native acceptance ceremony.
    """

    evidence: dict[str, successor.VerifiedEvidence]
    commits: dict[str, successor.GitCommit]
    tags: dict[str, successor.VerifiedTag]
    artifacts: dict[tuple[str, str], bytes]
    signed_payloads: dict[str, bytes]
    ancestor: bool = True
    signature_override: successor.VerifiedSignature | None = None
    closure_changes: tuple[str, ...] = (successor.RECEIPT_PATH,)
    publication: successor.VerifiedEvidence | None = None

    def resolve_evidence(self, digest: str, kind: str) -> successor.VerifiedEvidence:
        try:
            return self.evidence[digest]
        except KeyError as exc:
            raise successor.SuccessorError(f"missing authenticated {kind}") from exc

    def resolve_commit(self, oid: str) -> successor.GitCommit:
        try:
            return self.commits[oid]
        except KeyError as exc:
            raise successor.SuccessorError("unresolved Git commit") from exc

    def require_ancestor(self, ancestor: str, descendant: str) -> None:
        if not self.ancestor or (ancestor, descendant) != (successor.PREDECESSOR_CLOSURE, RESULT):
            raise successor.SuccessorError("not an authenticated C2 descendant")

    def resolve_tag(self, name: str) -> successor.VerifiedTag:
        try:
            return self.tags[name]
        except KeyError as exc:
            raise successor.SuccessorError("missing authenticated fixed tag") from exc

    def read_commit_artifact(self, commit: str, path: str) -> bytes:
        try:
            return self.artifacts[commit, path]
        except KeyError as exc:
            raise successor.SuccessorError("missing committed artifact") from exc

    def resolve_publication(self, tag: successor.VerifiedTag) -> successor.VerifiedEvidence:
        if self.publication is None:
            raise successor.SuccessorError("missing authenticated publication observation")
        return self.publication

    def changed_paths(self, base_commit: str, target_commit: str) -> tuple[str, ...]:
        if (base_commit, target_commit) != (RESULT, CLOSURE):
            raise successor.SuccessorError("wrong diff subject")
        return self.closure_changes

    def verify_signature(
        self, payload: bytes, envelope: Any, purpose: str
    ) -> successor.VerifiedSignature:
        if purpose != "s1-successor-acceptance/v3":
            raise successor.SuccessorError("wrong signature purpose")
        if self.signed_payloads.get(envelope["signature"]) != payload:
            raise successor.SuccessorError("synthetic verifier rejected signature")
        return self.signature_override or verified_signature(payload, moment("14:01"))


def verified_signature(payload: bytes, verified_at: str) -> successor.VerifiedSignature:
    return successor.VerifiedSignature(
        payload_sha256=successor.content_digest(payload),
        signer_person_id="maintainer",
        role="repository_maintainer",
        competence_scopes=("planning_governance:s1_successor",),
        trust_snapshot_digest=TRUST,
        valid_from_utc="2026-11-01T00:00:00Z",
        valid_until_utc=EXPIRY,
        verification_completed_at_utc=verified_at,
    )


@dataclass
class Fixture:
    policy: successor.SuccessorPolicy
    boundary: SyntheticTrustedBoundary
    pending: dict[str, Any]

    def accepted(self) -> dict[str, Any]:
        record, payload = successor.accepted_signing_claim(self.pending)
        token = successor.content_digest(payload)
        record["signature_envelope"] = {
            "profile": successor.SIGNATURE_PROFILE,
            "namespace": successor.SIGNATURE_NAMESPACE,
            "signer_person_id": "maintainer",
            "key_id": "synthetic-test-key",
            "signature": token,
        }
        self.boundary.signed_payloads[token] = payload
        return record

    def alter_evidence(self, field: str, mutate: Any) -> None:
        old_reference = self.pending[field]
        old = self.boundary.evidence[old_reference]
        document = json.loads(old.canonical_payload)
        mutate(document)
        evidence = successor.VerifiedEvidence(successor.canonical_bytes(document))
        reference = successor.evidence_digest(evidence)
        self.boundary.evidence[reference] = evidence
        self.pending[field] = reference
        self.pending["receipt_digest"] = successor.receipt_digest(self.pending)

    def closure(self, record: dict[str, Any]) -> str:
        stored = successor.canonical_bytes(record) + b"\n"
        self.boundary.artifacts[CLOSURE, successor.RECEIPT_PATH] = stored
        claim = {
            "format": "agent-assure-s1-current-acceptance-attestation/3",
            "acceptance_generation": 3,
            "predecessor_closure_commit": successor.PREDECESSOR_CLOSURE,
            "result_commit": RESULT,
            "closure_commit": CLOSURE,
            "receipt_path": successor.RECEIPT_PATH,
            "receipt_sha256": successor.content_digest(stored),
            "receipt_digest": record["receipt_digest"],
            "prepared_at_utc": moment("14:05"),
            "finalize_by_utc": moment("14:50"),
        }
        payload = successor.canonical_bytes(claim)
        self.boundary.tags[successor.SUCCESSOR_TAG] = successor.VerifiedTag(
            "f" * 40, CLOSURE, payload, verified_signature(payload, moment("14:06"))
        )
        publication = add_evidence(
            self.boundary,
            "fixed-tag-publication",
            CLOSURE,
            {
                "tag_object": "f" * 40,
                "closure_commit": CLOSURE,
                "tag_claim_sha256": successor.content_digest(payload),
                "receipt_sha256": successor.content_digest(stored),
                "published_at_utc": moment("14:06"),
                "readback_completed_at_utc": moment("14:06"),
                "clock_basis": "maintainer_host_utc_externally_unattested",
                "actual_signature_time_claimed": False,
            },
            issued=moment("14:06"),
        )
        self.boundary.publication = self.boundary.evidence[publication]
        return add_evidence(
            self.boundary,
            "standalone-historical-replay",
            CLOSURE,
            {
                "tag_object": "f" * 40,
                "receipt_sha256": successor.content_digest(stored),
                "mode": "standalone_clone_no_local",
                "exit_code": 0,
                "started_at_utc": moment("14:07"),
                "completed_at_utc": moment("14:15"),
                "validator_digest": SOURCE,
                "publication_evidence_digest": publication,
            },
            issued=moment("14:16"),
        )


def add_evidence(
    boundary: SyntheticTrustedBoundary,
    kind: str,
    subject: str,
    payload: dict[str, Any],
    *,
    issued: str = moment("13:30"),
) -> str:
    document = {
        "format": "agent-assure-s1-successor-evidence/3",
        "kind": kind,
        "subject_commit": subject,
        "issued_at_utc": issued,
        "valid_until_utc": EXPIRY,
        "payload": payload,
    }
    evidence = successor.VerifiedEvidence(successor.canonical_bytes(document))
    digest = successor.evidence_digest(evidence)
    boundary.evidence[digest] = evidence
    return digest


@pytest.fixture
def fixture() -> Fixture:
    policy = successor.SuccessorPolicy(
        trust_snapshot_digest=TRUST,
        signer_person_id="maintainer",
        workflow_digest=WORKFLOW,
        expected_validator_digest=SOURCE,
        required_ci_instances=successor.MANDATORY_CI_INSTANCES,
        required_local_checks=successor.MANDATORY_LOCAL_CHECKS,
        required_native_controls=successor.MANDATORY_NATIVE_CONTROLS,
        predecessor_tag_objects=(
            ("agent-assure-s1-1.0.0a1-acceptance", "d" * 40),
            ("agent-assure-s1-1.0.0a1-acceptance-v2", "e" * 40),
        ),
    )
    boundary = SyntheticTrustedBoundary(
        evidence={},
        commits={
            RESULT: successor.GitCommit(RESULT, (PARENT,)),
            CLOSURE: successor.GitCommit(CLOSURE, (RESULT,)),
        },
        tags={},
        artifacts={},
        signed_payloads={},
    )
    for name, oid in policy.predecessor_tag_objects:
        payload = b"historical-synthetic-claim"
        boundary.tags[name] = successor.VerifiedTag(
            oid,
            successor.PREDECESSOR_CLOSURE,
            payload,
            verified_signature(payload, moment("11:00")),
        )
    payloads: dict[str, dict[str, Any]] = {
        "prospective-kickoff": {
            "claim_digest": KICKOFF,
            "scope_digest": SCOPE,
            "signature_verification_completed_at_utc": moment("11:00"),
            "policy_digest": successor.successor_policy_digest(policy),
        },
        "result-observation": {
            "work_started_at_utc": moment("11:05"),
            "commit_observed_at_utc": moment("12:00"),
            "scope_digest": SCOPE,
            "allowed_paths": ["scripts/new.py"],
            "changed_paths": ["scripts/new.py"],
        },
        "native-full-suite-v4": {
            "source_format": "agent-assure-s1-post-r2-suite-evidence/4",
            "kickoff_claim_digest": KICKOFF,
            "started_at_utc": moment("12:05"),
            "completed_at_utc": moment("12:30"),
            "exit_code": 0,
            "collected": 100,
            "passed": 95,
            "skipped": 5,
            "failed": 0,
            "errors": 0,
            "deselected": 0,
            "control_ids": list(policy.required_native_controls),
            "source_record_digest": SOURCE,
        },
        "complete-local-checks": {
            "checks": [
                {
                    "id": identity,
                    "started_at_utc": moment("12:05"),
                    "completed_at_utc": moment("12:40"),
                    "exit_code": 0,
                    "output_digest": SOURCE,
                }
                for identity in policy.required_local_checks
            ],
        },
        "hosted-ci": {
            "repository": "acblabs/agent-assure",
            "workflow_path": ".github/workflows/ci.yml",
            "workflow_digest": WORKFLOW,
            "head_sha": RESULT,
            "run_id": "12345",
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "jobs": [
                {
                    "instance_id": identity,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at_utc": moment("12:01"),
                    "completed_at_utc": moment("13:00"),
                }
                for identity in policy.required_ci_instances
            ],
        },
        "scoped-roster": {
            "person_id": "maintainer",
            "competence_scopes": ["planning_governance:s1_successor", "schema_compatibility"],
            "mode": "maintainer_development",
            "independence": "NO_INDEPENDENT_REVIEW",
            "conflicts": ["self-review"],
            "review_capacity": "bounded declared capacity",
        },
        "fresh-forecast": {
            "baseline_commit": RESULT,
            "scope_digest": SCOPE,
            "disposition": "human_accepted_after_dispatch_scope_rebaseline",
            "forecast_digest": SOURCE,
            "acceptance_receipt_digest": SOURCE,
        },
        "scoped-signing-key": {
            "person_id": "maintainer",
            "trust_snapshot_digest": TRUST,
            "allowed_scopes": ["s1_successor_governance", "s2_development_governance"],
        },
    }
    references = {}
    for field, kind in successor.EVIDENCE_REFERENCE_FIELDS.items():
        is_kickoff = kind == "prospective-kickoff"
        references[field] = add_evidence(
            boundary,
            kind,
            successor.PREDECESSOR_CLOSURE if is_kickoff else RESULT,
            payloads[kind],
            issued=moment("11:01") if is_kickoff else moment("13:30"),
        )
    pending = successor.prepare_successor_acceptance(
        result_commit=RESULT,
        result_parent_commit=PARENT,
        scope_digest=SCOPE,
        kickoff_claim_digest=KICKOFF,
        evidence_references=references,
        policy=policy,
        boundary=boundary,
        now=PREPARE_NOW,
    )
    return Fixture(policy, boundary, pending)


def validate(fixture: Fixture, record: dict[str, Any] | None = None) -> str:
    return successor.validate_successor_receipt(
        record or fixture.accepted(),
        policy=fixture.policy,
        boundary=fixture.boundary,
        now=VERIFY_NOW,
    )


def test_preparation_is_pending_and_deterministic(fixture: Fixture) -> None:
    assert fixture.pending["status"] == "pending_human_review"
    assert fixture.pending["signature_envelope"] is None
    assert fixture.pending["actual_signature_time_claimed"] is False
    assert "closure_commit" not in fixture.pending
    assert successor.receipt_digest(fixture.pending) == fixture.pending["receipt_digest"]
    with pytest.raises(successor.SuccessorError, match="pending"):
        validate(fixture, fixture.pending)


def test_synthetic_authenticated_receipt_accepts_exact_all_check_graph(fixture: Fixture) -> None:
    record = fixture.accepted()
    assert validate(fixture, record) == record["receipt_digest"]
    schema = json.loads(
        (ROOT / "docs/governance/v1/sprint2/s1-successor-acceptance.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(fixture.pending)
    Draft202012Validator(schema).validate(record)


def test_synthetic_closure_accepts_acyclic_signed_subject_and_later_replay(
    fixture: Fixture,
) -> None:
    record = fixture.accepted()
    history = fixture.closure(record)
    result = successor.validate_successor_closure(
        record,
        closure_commit=CLOSURE,
        historical_replay_digest=history,
        policy=fixture.policy,
        boundary=fixture.boundary,
        now=VERIFY_NOW,
    )
    assert result.result_commit == RESULT and result.closure_commit == CLOSURE
    assert result.independent_review == "NO_INDEPENDENT_REVIEW"
    assert result.authorization_effect == "development_governance_only"


@pytest.mark.parametrize("field", list(successor.EVIDENCE_REFERENCE_FIELDS))
def test_every_authenticated_prerequisite_is_required(fixture: Fixture, field: str) -> None:
    del fixture.boundary.evidence[fixture.pending[field]]
    with pytest.raises(successor.SuccessorError, match="missing authenticated"):
        validate(fixture)


@pytest.mark.parametrize("field", list(successor.EVIDENCE_REFERENCE_FIELDS))
def test_each_evidence_subject_is_exact(fixture: Fixture, field: str) -> None:
    fixture.alter_evidence(field, lambda value: value.update(subject_commit="9" * 40))
    with pytest.raises(successor.SuccessorError, match="subject substitution"):
        validate(fixture)


@pytest.mark.parametrize("field", list(successor.EVIDENCE_REFERENCE_FIELDS))
def test_each_evidence_expiry_is_rechecked(fixture: Fixture, field: str) -> None:
    fixture.alter_evidence(field, lambda value: value.update(valid_until_utc=moment("14:10")))
    with pytest.raises(successor.SuccessorError, match="expired evidence"):
        validate(fixture)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda p: p["jobs"].pop(),
        lambda p: p["jobs"].append(copy.deepcopy(p["jobs"][0])),
        lambda p: p["jobs"][0].update(conclusion="skipped"),
        lambda p: p["jobs"][0].update(conclusion="cancelled"),
        lambda p: p["jobs"][0].update(conclusion="neutral"),
        lambda p: p["jobs"][0].update(status="in_progress"),
        lambda p: p.update(head_sha="9" * 40),
        lambda p: p.update(workflow_digest=SOURCE),
        lambda p: p.update(repository="attacker/fork"),
        lambda p: p.update(run_attempt=True),
        lambda p: p["jobs"][0].update(started_at_utc=moment("11:59")),
        lambda p: p["jobs"][0].update(completed_at_utc=moment("14:10")),
    ],
)
def test_ci_matrix_is_complete_successful_and_bound(fixture: Fixture, mutator: Any) -> None:
    fixture.alter_evidence(
        "hosted_ci_evidence_digest", lambda document: mutator(document["payload"])
    )
    with pytest.raises(successor.SuccessorError):
        validate(fixture)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda p: p.update(kickoff_claim_digest=SOURCE),
        lambda p: p.update(source_format="agent-assure-s1-post-r2-suite-evidence/3"),
        lambda p: p.update(exit_code=1),
        lambda p: p.update(passed=True),
        lambda p: p.update(collected=101),
        lambda p: p.update(failed=1),
        lambda p: p.update(errors=1),
        lambda p: p.update(deselected=1),
        lambda p: p.update(control_ids=[]),
        lambda p: p.update(started_at_utc=moment("11:59")),
    ],
)
def test_native_control_only_partial_failed_or_bool_evidence_cannot_accept(
    fixture: Fixture, mutator: Any
) -> None:
    fixture.alter_evidence("native_suite_evidence_digest", lambda d: mutator(d["payload"]))
    with pytest.raises(successor.SuccessorError):
        validate(fixture)


@pytest.mark.parametrize(
    "field,mutator",
    [
        (
            "kickoff_evidence_digest",
            lambda p: p.update(signature_verification_completed_at_utc=moment("11:06")),
        ),
        ("kickoff_evidence_digest", lambda p: p.update(scope_digest=SOURCE)),
        ("result_evidence_digest", lambda p: p.update(changed_paths=["src/privileged.py"])),
        ("local_checks_evidence_digest", lambda p: p["checks"].pop()),
        ("local_checks_evidence_digest", lambda p: p["checks"][0].update(exit_code=1)),
        (
            "local_checks_evidence_digest",
            lambda p: p["checks"].append(copy.deepcopy(p["checks"][0])),
        ),
        (
            "roster_evidence_digest",
            lambda p: p.update(competence_scopes=["repository_maintenance"]),
        ),
        ("roster_evidence_digest", lambda p: p.update(independence="independently_reviewed")),
        ("roster_evidence_digest", lambda p: p.update(review_capacity="")),
        ("forecast_evidence_digest", lambda p: p.update(baseline_commit=PARENT)),
        ("forecast_evidence_digest", lambda p: p.update(disposition="pending")),
        (
            "signing_key_evidence_digest",
            lambda p: p.update(allowed_scopes=["s1_successor_governance"]),
        ),
    ],
)
def test_prospective_scope_roster_forecast_and_key_extension_are_not_implied(
    fixture: Fixture, field: str, mutator: Any
) -> None:
    fixture.alter_evidence(field, lambda d: mutator(d["payload"]))
    with pytest.raises(successor.SuccessorError):
        validate(fixture)


@pytest.mark.parametrize("parents", [(), (PARENT, "8" * 40), (RESULT,)])
def test_result_nonmerge_acyclic_topology_is_required(
    fixture: Fixture, parents: tuple[str, ...]
) -> None:
    fixture.boundary.commits[RESULT] = successor.GitCommit(RESULT, parents)
    with pytest.raises(successor.SuccessorError):
        validate(fixture)


def test_result_must_properly_descend_from_immutable_predecessor(fixture: Fixture) -> None:
    fixture.boundary.ancestor = False
    with pytest.raises(successor.SuccessorError, match="descendant"):
        validate(fixture)


def test_predecessor_tag_rewrite_is_rejected(fixture: Fixture) -> None:
    name = fixture.policy.predecessor_tag_objects[1][0]
    fixture.boundary.tags[name] = replace(fixture.boundary.tags[name], object_oid="8" * 40)
    with pytest.raises(successor.SuccessorError, match="predecessor tag changed"):
        validate(fixture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("acceptance_generation", True),
        ("actual_signature_time_claimed", True),
        ("clock_basis", "independently_attested"),
        ("authorization_effect", "runtime_authorization"),
        ("predecessor_closure_commit", "8" * 40),
        ("result_commit", RESULT + "\n"),
        ("unexpected", "extra"),
    ],
)
def test_closed_strict_receipt_cannot_launder_flags(
    fixture: Fixture, field: str, value: object
) -> None:
    record = fixture.accepted()
    record[field] = value
    record["receipt_digest"] = successor.receipt_digest(record)
    with pytest.raises(successor.SuccessorError):
        validate(fixture, record)


def test_signature_substitution_and_missing_scoped_authority_fail(fixture: Fixture) -> None:
    record = fixture.accepted()
    record["signature_envelope"]["signature"] = "attacker-claimed-success"
    with pytest.raises(successor.SuccessorError, match="rejected signature"):
        validate(fixture, record)
    record = fixture.accepted()
    fixture.boundary.signature_override = replace(
        verified_signature(successor.signature_claim(record), moment("14:01")), competence_scopes=()
    )
    with pytest.raises(successor.SuccessorError, match="competence"):
        validate(fixture, record)


def test_self_reported_verification_dict_is_not_verified_evidence(fixture: Fixture) -> None:
    reference = fixture.pending["native_suite_evidence_digest"]
    fixture.boundary.evidence[reference] = {"verified": True}  # type: ignore[assignment]
    with pytest.raises(successor.SuccessorError, match="verified evidence object"):
        validate(fixture)


@pytest.mark.parametrize(
    "attack",
    ["wrong-parent", "wrong-tag", "blob-tamper", "missing-history", "late-tag", "wrong-history"],
)
def test_closure_requires_exact_blob_tag_window_and_standalone_replay(
    fixture: Fixture, attack: str
) -> None:
    record = fixture.accepted()
    history = fixture.closure(record)
    if attack == "wrong-parent":
        fixture.boundary.commits[CLOSURE] = successor.GitCommit(CLOSURE, (PARENT,))
    elif attack == "wrong-tag":
        fixture.boundary.tags[successor.SUCCESSOR_TAG] = replace(
            fixture.boundary.tags[successor.SUCCESSOR_TAG], target_commit=RESULT
        )
    elif attack == "blob-tamper":
        fixture.boundary.artifacts[CLOSURE, successor.RECEIPT_PATH] += b" "
    elif attack == "missing-history":
        del fixture.boundary.evidence[history]
    elif attack == "late-tag":
        tag = fixture.boundary.tags[successor.SUCCESSOR_TAG]
        fixture.boundary.tags[successor.SUCCESSOR_TAG] = replace(
            tag, signature=replace(tag.signature, verification_completed_at_utc=moment("14:51"))
        )
    else:
        old = json.loads(fixture.boundary.evidence[history].canonical_payload)
        history = add_evidence(
            fixture.boundary, "standalone-historical-replay", RESULT, old["payload"]
        )
    with pytest.raises(successor.SuccessorError):
        successor.validate_successor_closure(
            record,
            closure_commit=CLOSURE,
            historical_replay_digest=history,
            policy=fixture.policy,
            boundary=fixture.boundary,
            now=VERIFY_NOW,
        )


def test_empty_trusted_expected_ci_matrix_cannot_accept(fixture: Fixture) -> None:
    fixture.policy = replace(fixture.policy, required_ci_instances=())
    with pytest.raises(successor.SuccessorError, match="empty"):
        validate(fixture)


def test_receipt_expiry_and_excessive_lifetime_fail(fixture: Fixture) -> None:
    record = fixture.accepted()
    with pytest.raises(successor.SuccessorError, match="stale"):
        successor.validate_successor_receipt(
            record,
            policy=fixture.policy,
            boundary=fixture.boundary,
            now=datetime(2027, 1, 1, tzinfo=UTC),
        )
    fixture.pending["valid_until_utc"] = "2027-01-01T00:00:00Z"
    fixture.pending["receipt_digest"] = successor.receipt_digest(fixture.pending)
    with pytest.raises(successor.SuccessorError, match="excessive"):
        validate(fixture)


def test_duplicate_json_evidence_is_rejected_before_semantic_use(fixture: Fixture) -> None:
    reference = fixture.pending["native_suite_evidence_digest"]
    evidence = fixture.boundary.evidence[reference]
    malformed = evidence.canonical_payload.replace(b"{", b'{"kind":"forged",', 1)
    bad = successor.VerifiedEvidence(malformed)
    digest = successor.evidence_digest(bad)
    fixture.boundary.evidence[digest] = bad
    fixture.pending["native_suite_evidence_digest"] = digest
    fixture.pending["receipt_digest"] = successor.receipt_digest(fixture.pending)
    with pytest.raises(successor.SuccessorError, match="duplicate JSON"):
        validate(fixture)


def kickoff_options() -> dict[str, Any]:
    return {
        "base_commit": PARENT,
        "allowed_paths": (
            "scripts/v1_s1_successor.py",
            "docs/adr/0017-v1-evidence-temporal-semantics.md",
        ),
        "work_limits": {
            "maximum_changed_files": 20,
            "maximum_diff_lines": 20000,
            "maximum_wall_clock_seconds": 86400,
        },
        "policy_digest": SOURCE,
        "schema_digest": TRUST,
        "signer_person_id": "maintainer",
    }


def test_kickoff_request_is_deterministic_scope_bound_without_future_evidence() -> None:
    options = kickoff_options()
    claim, request = successor.prepare_kickoff_claim(**options)
    reverse = {**options, "allowed_paths": tuple(reversed(options["allowed_paths"]))}
    assert (claim, request) == successor.prepare_kickoff_claim(**reverse)
    assert request.decision_status == "pending_human_decision"
    assert request.claim_sha256 == successor.content_digest(request.canonical_claim)
    assert request.signature_namespace == successor.SIGNATURE_NAMESPACE
    assert "result_commit" not in claim and "issued_at_utc" not in claim
    assert "signature_envelope" not in claim
    assert claim["signature_time_capability"] == "none"
    schema = json.loads(
        (ROOT / "docs/governance/v1/sprint2/s1-successor-acceptance.schema.json").read_text()
    )
    Draft202012Validator({"$ref": "#/$defs/kickoff_claim", "$defs": schema["$defs"]}).validate(
        claim
    )
    changed, _ = successor.prepare_kickoff_claim(
        **{**options, "allowed_paths": ("scripts/other.py",)}
    )
    assert changed["scope_digest"] != claim["scope_digest"]


@pytest.mark.parametrize(
    "paths",
    [
        (),
        ("../escape.py",),
        ("/absolute.py",),
        ("C:/absolute.py",),
        ("scripts\\alias.py",),
        ("scripts//empty.py",),
        (".git/config",),
        (".aws/credentials",),
        (".claude/settings.json",),
        ("a.py", "a.py"),
    ],
)
def test_kickoff_never_invents_or_broadens_exact_file_scope(paths: tuple[str, ...]) -> None:
    with pytest.raises(successor.SuccessorError):
        successor.prepare_kickoff_claim(**{**kickoff_options(), "allowed_paths": paths})


def test_kickoff_work_limits_cannot_be_bool_or_omit_an_obligation() -> None:
    options = kickoff_options()
    options["work_limits"]["maximum_changed_files"] = True
    with pytest.raises(successor.SuccessorError, match="strict integer"):
        successor.prepare_kickoff_claim(**options)
    options = kickoff_options()
    del options["work_limits"]["maximum_diff_lines"]
    with pytest.raises(successor.SuccessorError, match="exact kickoff work"):
        successor.prepare_kickoff_claim(**options)


def test_receipt_signing_request_does_not_supply_human_decision_or_signature(
    fixture: Fixture,
) -> None:
    template, request = successor.prepare_receipt_signing_request(fixture.pending)
    assert fixture.pending["status"] == "pending_human_review"
    assert template["signature_envelope"] is None
    assert request.decision_status == "pending_human_decision"
    assert request.canonical_claim == successor.signature_claim(template)
    with pytest.raises(successor.SuccessorError, match="closed JSON object"):
        validate(fixture, template)


def test_public_receipt_loader_rejects_duplicate_fields_and_nonfinite_json(
    fixture: Fixture,
) -> None:
    payload = successor.canonical_bytes(fixture.pending)
    assert successor.load_successor_receipt(payload) == fixture.pending
    duplicate = payload.replace(b"{", b'{"acceptance_generation":3,', 1)
    with pytest.raises(successor.SuccessorError, match="duplicate JSON"):
        successor.load_successor_receipt(duplicate)
    with pytest.raises(successor.SuccessorError, match="noninteger/nonfinite"):
        successor.load_successor_receipt(b'{"acceptance_generation": NaN}')


@pytest.mark.parametrize(
    "paths",
    [
        (".Git/config",),
        (".GIT",),
        (".AWS",),
        (".ClAuDe/settings.json",),
        (".codex/config.json",),
        (".agents/rules.md",),
        ("*.py",),
        ("scripts/?.py",),
        ("scripts/[ab].py",),
        ("scripts/CON",),
        ("scripts/CON.txt",),
        ("scripts/AUX .txt",),
        ("scripts/clock$.x",),
        ("scripts/CONIN$.txt",),
        ("scripts/LPT1.py",),
        ("scripts/COM¹.py",),
        ("scripts/com²",),
        ("scripts/LPT³.log",),
        ("scripts/LPT⁴.log",),
        ("file.py.",),
        ("docs /a.md",),
        (" leading.py",),
        ("a\x7f.py",),
        ("a\u200b.py",),
        ("Foo.py", "foo.py"),
        ("scripts/a:b.py",),
        ("scripts/pipe|.py",),
    ],
)
def test_kickoff_rejects_windows_aliases_devices_globs_and_private_metadata(
    paths: tuple[str, ...],
) -> None:
    with pytest.raises(successor.SuccessorError):
        successor.prepare_kickoff_claim(**{**kickoff_options(), "allowed_paths": paths})


@pytest.mark.parametrize(
    "field,mutate",
    [
        ("result_evidence_digest", lambda p: p.update(commit_observed_at_utc=moment("13:45"))),
        ("native_suite_evidence_digest", lambda p: p.update(completed_at_utc=moment("13:45"))),
        (
            "local_checks_evidence_digest",
            lambda p: p["checks"][0].update(completed_at_utc=moment("13:45")),
        ),
        (
            "hosted_ci_evidence_digest",
            lambda p: p["jobs"][0].update(completed_at_utc=moment("13:45")),
        ),
    ],
)
def test_evidence_cannot_claim_completion_after_its_own_issue(
    fixture: Fixture,
    field: str,
    mutate: Any,
) -> None:
    fixture.alter_evidence(field, lambda document: mutate(document["payload"]))
    with pytest.raises(successor.SuccessorError):
        validate(fixture)


@pytest.mark.parametrize("field", list(successor.EVIDENCE_REFERENCE_FIELDS))
def test_source_specific_evidence_payloads_are_closed(fixture: Fixture, field: str) -> None:
    fixture.alter_evidence(field, lambda document: document["payload"].update(verified=True))
    with pytest.raises(successor.SuccessorError, match="extra object fields"):
        validate(fixture)


@pytest.mark.parametrize(
    "field", ["required_ci_instances", "required_local_checks", "required_native_controls"]
)
def test_nonempty_trusted_policy_cannot_silently_drop_mandatory_controls(
    fixture: Fixture, field: str
) -> None:
    fixture.policy = replace(fixture.policy, **{field: ("arbitrary-one-control",)})
    with pytest.raises(successor.SuccessorError, match="omits mandatory"):
        validate(fixture)


def test_prospective_kickoff_binds_full_verifier_policy(fixture: Fixture) -> None:
    fixture.policy = replace(fixture.policy, finalization_window_seconds=1800)
    with pytest.raises(successor.SuccessorError, match="exact verifier policy"):
        validate(fixture)


@pytest.mark.parametrize(
    "changes",
    [
        (),
        (successor.RECEIPT_PATH, "src/agent_assure/ci.py"),
        (successor.RECEIPT_PATH, ".github/workflows/ci.yml"),
        (successor.RECEIPT_PATH, "scripts/v1_s1_successor.py"),
    ],
)
def test_closure_cannot_change_tested_r3_source_or_workflow(
    fixture: Fixture,
    changes: tuple[str, ...],
) -> None:
    record = fixture.accepted()
    history = fixture.closure(record)
    fixture.boundary.closure_changes = changes
    with pytest.raises(successor.SuccessorError, match="C3 may change only"):
        successor.validate_successor_closure(
            record,
            closure_commit=CLOSURE,
            historical_replay_digest=history,
            policy=fixture.policy,
            boundary=fixture.boundary,
            now=VERIFY_NOW,
        )


def test_historical_replay_validator_is_pinned_not_merely_well_formed(fixture: Fixture) -> None:
    record = fixture.accepted()
    reference = fixture.closure(record)
    document = json.loads(fixture.boundary.evidence[reference].canonical_payload)
    document["payload"]["validator_digest"] = WORKFLOW
    changed = successor.VerifiedEvidence(successor.canonical_bytes(document))
    digest = successor.evidence_digest(changed)
    fixture.boundary.evidence[digest] = changed
    with pytest.raises(successor.SuccessorError, match="unpinned validator"):
        successor.validate_successor_closure(
            record,
            closure_commit=CLOSURE,
            historical_replay_digest=digest,
            policy=fixture.policy,
            boundary=fixture.boundary,
            now=VERIFY_NOW,
        )


def test_minimum_ci_matrix_matches_public_successor_contract() -> None:
    protocol = json.loads(
        (ROOT / "docs/governance/v1/sprint2/s1-successor-protocol.json").read_text()
    )
    expected = {
        successor.ci_instance_id(row["job_id"], row["matrix"])
        for row in protocol["required_ci_instances"]
    }
    assert set(successor.MANDATORY_CI_INSTANCES) == expected
    assert set(successor.MANDATORY_NATIVE_CONTROLS) == set(protocol["mandatory_controls"])
    assert set(successor.MANDATORY_LOCAL_CHECKS) == (
        set(protocol["required_local_check_targets"])
        - {"native_full_suite_v4_capture", "standalone_historical_replay"}
    )


def publication_document(fixture: Fixture) -> dict[str, Any]:
    assert fixture.boundary.publication is not None
    return json.loads(fixture.boundary.publication.canonical_payload)


def replace_publication(fixture: Fixture, mutate: Any) -> None:
    document = publication_document(fixture)
    mutate(document)
    fixture.boundary.publication = successor.VerifiedEvidence(successor.canonical_bytes(document))


def test_subject_validation_is_nonaccepted_and_does_not_require_recursive_history(
    fixture: Fixture,
) -> None:
    record = fixture.accepted()
    history = fixture.closure(record)
    del fixture.boundary.evidence[history]
    result = successor.validate_successor_subject(
        record,
        closure_commit=CLOSURE,
        policy=fixture.policy,
        boundary=fixture.boundary,
        now=VERIFY_NOW,
    )
    assert type(result) is successor.ValidatedClosureSubject
    assert result.authorization_effect == "none"
    assert result.fixed_tag_object == "f" * 40
    assert fixture.boundary.publication is not None
    assert result.publication_evidence_digest == successor.evidence_digest(
        fixture.boundary.publication
    )
    with pytest.raises(successor.SuccessorError, match="missing authenticated"):
        successor.validate_successor_closure(
            record,
            closure_commit=CLOSURE,
            historical_replay_digest=history,
            policy=fixture.policy,
            boundary=fixture.boundary,
            now=VERIFY_NOW,
        )


def refresh_signature_checks(fixture: Fixture, record: dict[str, Any]) -> None:
    fixture.boundary.signature_override = verified_signature(
        successor.signature_claim(record), moment("16:01")
    )
    tag = fixture.boundary.tags[successor.SUCCESSOR_TAG]
    fixture.boundary.tags[successor.SUCCESSOR_TAG] = replace(
        tag, signature=verified_signature(tag.canonical_claim, moment("16:01"))
    )


def test_later_crypto_reverification_preserves_original_publication_and_history(
    fixture: Fixture,
) -> None:
    record = fixture.accepted()
    history = fixture.closure(record)
    refresh_signature_checks(fixture, record)
    result = successor.validate_successor_closure(
        record,
        closure_commit=CLOSURE,
        historical_replay_digest=history,
        policy=fixture.policy,
        boundary=fixture.boundary,
        now=datetime(2026, 11, 7, 16, 20, tzinfo=UTC),
    )
    assert result.authorization_effect == "development_governance_only"
    assert result.historical_replay_digest == history
    assert result.publication_evidence_digest


def test_new_standalone_replay_can_run_after_original_one_hour_window(
    fixture: Fixture,
) -> None:
    record = fixture.accepted()
    original_history = fixture.closure(record)
    refresh_signature_checks(fixture, record)
    document = json.loads(fixture.boundary.evidence[original_history].canonical_payload)
    document["payload"]["started_at_utc"] = moment("16:02")
    document["payload"]["completed_at_utc"] = moment("16:10")
    history = add_evidence(
        fixture.boundary,
        "standalone-historical-replay",
        CLOSURE,
        document["payload"],
        issued=moment("16:11"),
    )
    result = successor.validate_successor_closure(
        record,
        closure_commit=CLOSURE,
        historical_replay_digest=history,
        policy=fixture.policy,
        boundary=fixture.boundary,
        now=datetime(2026, 11, 7, 16, 20, tzinfo=UTC),
    )
    assert result.historical_replay_digest == history


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update(kind="self-reported-publication"),
        lambda doc: doc.update(subject_commit=RESULT),
        lambda doc: doc["payload"].update(tag_object="8" * 40),
        lambda doc: doc["payload"].update(closure_commit=RESULT),
        lambda doc: doc["payload"].update(tag_claim_sha256=SOURCE),
        lambda doc: doc["payload"].update(receipt_sha256=SOURCE),
        lambda doc: doc["payload"].update(published_at_utc=moment("14:04")),
        lambda doc: doc["payload"].update(readback_completed_at_utc=moment("14:05")),
        lambda doc: doc["payload"].update(
            published_at_utc=moment("14:50"), readback_completed_at_utc=moment("14:50")
        ),
        lambda doc: doc["payload"].update(readback_completed_at_utc=moment("14:51")),
        lambda doc: doc["payload"].update(clock_basis="independent_attestation_invented"),
        lambda doc: doc["payload"].update(actual_signature_time_claimed=True),
        lambda doc: doc["payload"].pop("tag_object"),
        lambda doc: doc["payload"].update(authenticated=True),
        lambda doc: doc.update(issued_at_utc=moment("14:05")),
        lambda doc: doc.update(issued_at_utc=moment("14:21")),
    ],
)
def test_publication_requires_authenticated_exact_subject_and_honest_original_window(
    fixture: Fixture,
    mutate: Any,
) -> None:
    record = fixture.accepted()
    fixture.closure(record)
    replace_publication(fixture, mutate)
    with pytest.raises(successor.SuccessorError):
        successor.validate_successor_subject(
            record,
            closure_commit=CLOSURE,
            policy=fixture.policy,
            boundary=fixture.boundary,
            now=VERIFY_NOW,
        )


@pytest.mark.parametrize("publication", [None, {"verified": True}, b"fake evidence"])
def test_missing_or_self_reported_publication_cannot_become_verified_evidence(
    fixture: Fixture,
    publication: Any,
) -> None:
    record = fixture.accepted()
    fixture.closure(record)
    fixture.boundary.publication = publication
    with pytest.raises(successor.SuccessorError):
        successor.validate_successor_subject(
            record,
            closure_commit=CLOSURE,
            policy=fixture.policy,
            boundary=fixture.boundary,
            now=VERIFY_NOW,
        )


@pytest.mark.parametrize("digest", ["sha256:" + "9" * 64, None])
def test_standalone_replay_must_bind_exact_publication_evidence(
    fixture: Fixture,
    digest: str | None,
) -> None:
    record = fixture.accepted()
    original = fixture.closure(record)
    payload = json.loads(fixture.boundary.evidence[original].canonical_payload)["payload"]
    if digest is None:
        payload.pop("publication_evidence_digest")
    else:
        payload["publication_evidence_digest"] = digest
    history = add_evidence(
        fixture.boundary, "standalone-historical-replay", CLOSURE, payload, issued=moment("14:16")
    )
    with pytest.raises(successor.SuccessorError):
        successor.validate_successor_closure(
            record,
            closure_commit=CLOSURE,
            historical_replay_digest=history,
            policy=fixture.policy,
            boundary=fixture.boundary,
            now=VERIFY_NOW,
        )


def test_optional_source_witness_is_transitively_bound_by_evidence_reference(
    fixture: Fixture,
) -> None:
    previous = fixture.pending["native_suite_evidence_digest"]
    fixture.alter_evidence(
        "native_suite_evidence_digest", lambda doc: doc.update(source_witness_digest=SOURCE)
    )
    assert fixture.pending["native_suite_evidence_digest"] != previous
    assert validate(fixture)


@pytest.mark.parametrize("digest", [None, True, "not-a-digest", "sha256:" + "f" * 63])
def test_optional_source_witness_is_strict_sha256_when_present(
    fixture: Fixture,
    digest: Any,
) -> None:
    fixture.alter_evidence(
        "native_suite_evidence_digest", lambda doc: doc.update(source_witness_digest=digest)
    )
    with pytest.raises(successor.SuccessorError, match="SHA-256"):
        validate(fixture)
