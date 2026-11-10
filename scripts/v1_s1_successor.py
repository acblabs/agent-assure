"""Pure generation-3 S1 acceptance logic; no signing, execution, or autoaccept CLI.

The caller is the trusted boundary. It must authenticate the code/schema/policy
and supply resolvers backed by the frozen runtime, absolute authenticated Git
and OpenSSH tools, full S1 evidence validators, and authenticated hosted-CI
readback. ``VerifiedEvidence`` cannot be created from an untrusted JSON claim
that verification succeeded. This module never chooses a key, runs PATH tools,
fetches a URL, or turns a producer's success Boolean into verification.

The receipt lives in C3 and therefore binds R3, not C3. The external signed
fixed tag binds C3 and its exact receipt bytes. Standalone historical replay is
subsequent external evidence, avoiding a self-referential receipt/commit graph.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

import rfc8785

PREDECESSOR_CLOSURE = "db5133e09860d292047b963b0fb81b3e7385b7fa"
SUCCESSOR_TAG = "agent-assure-s1-1.0.0a1-acceptance-v3"
RECEIPT_PATH = "docs/governance/v1/sprint2/s1-successor-acceptance.json"
SIGNATURE_PROFILE = "openssh-sshsig-ed25519/v1"
SIGNATURE_NAMESPACE = "agent-assure-governance-v1"
EVIDENCE_REFERENCE_FIELDS = {
    "kickoff_evidence_digest": "prospective-kickoff",
    "result_evidence_digest": "result-observation",
    "native_suite_evidence_digest": "native-full-suite-v4",
    "local_checks_evidence_digest": "complete-local-checks",
    "hosted_ci_evidence_digest": "hosted-ci",
    "roster_evidence_digest": "scoped-roster",
    "forecast_evidence_digest": "fresh-forecast",
    "signing_key_evidence_digest": "scoped-signing-key",
}
MANDATORY_NATIVE_CONTROLS = (
    "python311_parse_and_import",
    "private_input_free_hosted_tests",
    "native_extension_and_reparse_inventory",
    "hidden_pytest_config_isolation",
    "complete_nondeselected_collection",
    "strict_JSON_types_and_terminal_totals",
    "frozen_runtime_and_absolute_host_tool_identities",
    "canonical_v4_local_git_metadata",
    "truthful_unattested_host_UTC_observations",
    "immutable_no_clobber_evidence_paths",
)
MANDATORY_LOCAL_CHECKS = (
    "make check schema-check",
    "successor_specific_unit_and_integration_checks",
)
_PAYLOAD_FIELDS = {
    "prospective-kickoff": {
        "claim_digest",
        "scope_digest",
        "policy_digest",
        "signature_verification_completed_at_utc",
    },
    "result-observation": {
        "work_started_at_utc",
        "commit_observed_at_utc",
        "scope_digest",
        "allowed_paths",
        "changed_paths",
    },
    "native-full-suite-v4": {
        "source_format",
        "kickoff_claim_digest",
        "started_at_utc",
        "completed_at_utc",
        "exit_code",
        "collected",
        "passed",
        "skipped",
        "failed",
        "errors",
        "deselected",
        "control_ids",
        "source_record_digest",
    },
    "complete-local-checks": {"checks"},
    "hosted-ci": {
        "repository",
        "workflow_path",
        "workflow_digest",
        "head_sha",
        "run_id",
        "run_attempt",
        "status",
        "conclusion",
        "jobs",
    },
    "scoped-roster": {
        "person_id",
        "competence_scopes",
        "mode",
        "independence",
        "conflicts",
        "review_capacity",
    },
    "fresh-forecast": {
        "baseline_commit",
        "scope_digest",
        "disposition",
        "forecast_digest",
        "acceptance_receipt_digest",
    },
    "scoped-signing-key": {"person_id", "trust_snapshot_digest", "allowed_scopes"},
}
_RECEIPT_FIELDS = {
    "format",
    "acceptance_generation",
    "status",
    "authorization_effect",
    "predecessor_closure_commit",
    "result_commit",
    "result_parent_commit",
    "scope_digest",
    "kickoff_claim_digest",
    "issued_at_utc",
    "valid_until_utc",
    "clock_basis",
    "actual_signature_time_claimed",
    "receipt_digest",
    "signature_envelope",
    *EVIDENCE_REFERENCE_FIELDS,
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OID = re.compile(r"[0-9a-f]{40}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")


class SuccessorError(ValueError):
    """An explicit missing, stale, untrusted, or inconsistent prerequisite."""


@dataclass(frozen=True)
class VerifiedEvidence:
    """Canonical, authenticated evidence returned only by a trusted resolver.

    The resolver must validate original signatures, authority, raw source bytes,
    and complete source-specific semantics before constructing this object.
    This wrapper is not itself a cryptographic capability or a trust root.
    """

    canonical_payload: bytes


@dataclass(frozen=True)
class VerifiedSignature:
    """Exact-byte signature and authority result from the trusted verifier."""

    payload_sha256: str
    signer_person_id: str
    role: str
    competence_scopes: tuple[str, ...]
    trust_snapshot_digest: str
    valid_from_utc: str
    valid_until_utc: str
    verification_completed_at_utc: str


@dataclass(frozen=True)
class GitCommit:
    oid: str
    parents: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedTag:
    """An authenticated, immutable annotated tag and verified signed claim."""

    object_oid: str
    target_commit: str
    canonical_claim: bytes
    # A predecessor fixed tag may be an explicitly pinned historical trust
    # anchor. That does not manufacture a fresh signature verification event.
    signature: VerifiedSignature | None


@dataclass(frozen=True)
class SuccessorPolicy:
    """Verifier-owned policy, never populated from the candidate receipt.

    CI instance identifiers must enumerate *every* expanded matrix instance
    from the pinned workflow. Plain job IDs are insufficient for matrix jobs.
    """

    trust_snapshot_digest: str
    signer_person_id: str
    workflow_digest: str
    expected_validator_digest: str
    required_ci_instances: tuple[str, ...]
    required_local_checks: tuple[str, ...]
    required_native_controls: tuple[str, ...]
    predecessor_tag_objects: tuple[tuple[str, str], ...]
    maximum_age_seconds: int = 30 * 24 * 60 * 60
    finalization_window_seconds: int = 3600


@dataclass(frozen=True)
class AcceptedSuccessor:
    """Verified development-governance closure, never runtime authority."""

    result_commit: str
    closure_commit: str
    receipt_digest: str
    fixed_tag_object: str
    historical_replay_digest: str
    authorization_effect: str = "development_governance_only"
    independent_review: str = "NO_INDEPENDENT_REVIEW"
    publication_evidence_digest: str = ""


@dataclass(frozen=True)
class ValidatedClosureSubject:
    """Verified subject/publication, not acceptance or standalone replay proof.

    This is the acyclic target for a real standalone verifier subprocess. Its
    successful return alone can never close the successor acceptance gate.
    """

    result_commit: str
    closure_commit: str
    receipt_digest: str
    receipt_sha256: str
    fixed_tag_object: str
    publication_evidence_digest: str
    published_at_utc: str
    readback_completed_at_utc: str
    authorization_effect: str = "none"


@dataclass(frozen=True)
class SigningRequest:
    """Reviewable claim bytes only; not a signature, acceptance, or authorization.

    A host adapter writes these exact bytes with no newline conversion and asks
    the assigned human to review and sign using the specified SSHSIG namespace.
    Imports must still authenticate scope, time, key, role, and signature.
    """

    purpose: str
    canonical_claim: bytes
    claim_sha256: str
    signature_namespace: str = SIGNATURE_NAMESPACE
    decision_status: str = "pending_human_decision"


class TrustedSuccessorBoundary(Protocol):
    """Implement only inside the pinned trusted verifier, never as JSON adapters."""

    def resolve_evidence(self, digest: str, kind: str) -> VerifiedEvidence: ...

    def resolve_commit(self, oid: str) -> GitCommit: ...

    def require_ancestor(self, ancestor: str, descendant: str) -> None: ...

    def resolve_tag(self, name: str) -> VerifiedTag: ...

    def resolve_publication(self, tag: VerifiedTag) -> VerifiedEvidence:
        """Verify countersigned original publication observations for this tag.

        The host authenticates the human adoption signature, exact source
        witness, immutable tag and raw receipt bindings before returning. A
        JSON success flag, signature verification time or Git tag date cannot
        establish when the original publication/read-back was observed.
        """
        ...

    def read_commit_artifact(self, commit: str, path: str) -> bytes: ...

    def changed_paths(self, base_commit: str, target_commit: str) -> tuple[str, ...]: ...

    def verify_signature(
        self, payload: bytes, envelope: Mapping[str, Any], purpose: str
    ) -> VerifiedSignature: ...


def canonical_bytes(value: object) -> bytes:
    try:
        return rfc8785.dumps(cast(Any, value))
    except (TypeError, ValueError) as exc:
        raise SuccessorError("unsupported canonical JSON value") from exc


def content_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def ci_instance_id(job_id: str, matrix: Mapping[str, str]) -> str:
    """Canonical workflow job/matrix identity; human display names are not IDs."""
    return canonical_bytes({"job_id": job_id, "matrix": dict(matrix)}).decode("utf-8")


MANDATORY_CI_INSTANCES = (
    *(
        ci_instance_id("test", {"python-version": version})
        for version in ("3.11", "3.12", "3.13", "3.14")
    ),
    *(
        ci_instance_id("dependency-lower-bounds", {"python-version": version})
        for version in ("3.11", "3.14")
    ),
    *(
        ci_instance_id("coverage-shards", {"shard": shard})
        for shard in ("unit-a", "unit-b1", "unit-b2", "unit-top", "integration")
    ),
    *(
        ci_instance_id("windows-containment", {"python-version": version})
        for version in ("3.11", "3.14")
    ),
    *(
        ci_instance_id(job, {})
        for job in (
            "composite-action-smoke",
            "composite-action-strict-smoke",
            "coverage-gate",
            "schema-immutability",
            "windows-governance",
            "langgraph-smoke",
            "adk-smoke",
            "otel-contract",
        )
    ),
)


def successor_policy_digest(policy: SuccessorPolicy) -> str:
    """Bind the complete verifier policy in the prospectively signed kickoff."""
    _validate_policy(policy)
    projection = {
        "format": "agent-assure-s1-successor-verifier-policy/3",
        "trust_snapshot_digest": policy.trust_snapshot_digest,
        "signer_person_id": policy.signer_person_id,
        "workflow_digest": policy.workflow_digest,
        "expected_validator_digest": policy.expected_validator_digest,
        "required_ci_instances": sorted(policy.required_ci_instances),
        "required_local_checks": sorted(policy.required_local_checks),
        "required_native_controls": sorted(policy.required_native_controls),
        "predecessor_tag_objects": [
            [name, oid] for name, oid in sorted(policy.predecessor_tag_objects)
        ],
        "maximum_age_seconds": policy.maximum_age_seconds,
        "finalization_window_seconds": policy.finalization_window_seconds,
    }
    return content_digest(
        b"agent-assure:s1-successor-verifier-policy/v3\x00" + canonical_bytes(projection)
    )


def evidence_digest(evidence: VerifiedEvidence) -> str:
    return content_digest(b"agent-assure:s1-successor-evidence/v3\x00" + evidence.canonical_payload)


def receipt_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_digest", "signature_envelope"}
    }


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    return content_digest(
        b"agent-assure:s1-successor-acceptance/v3\x00"
        + canonical_bytes(receipt_projection(receipt))
    )


def signature_claim(receipt: Mapping[str, Any]) -> bytes:
    """Exact domain-separated signing bytes; never contain the signature itself."""
    return b"agent-assure:s1-successor-acceptance-signature/v3\x00" + canonical_bytes(
        {**receipt_projection(receipt), "receipt_digest": receipt["receipt_digest"]}
    )


def prepare_kickoff_claim(
    *,
    base_commit: str,
    allowed_paths: tuple[str, ...],
    work_limits: Mapping[str, int],
    policy_digest: str,
    schema_digest: str,
    signer_person_id: str,
) -> tuple[dict[str, Any], SigningRequest]:
    """Prepare prospective exact-scope review without inventing R3 or a time.

    No result commit, execution evidence, human competence, signature, or time is
    fabricated. A later authenticated import observation establishes when the
    kickoff verification completed; a signature has no intrinsic timestamp.
    The trusted importer must resolve ``base_commit`` as a proper descendant of
    the immutable predecessor and bind these policy/schema bytes before edits.
    """
    _oid(base_commit)
    _digest(policy_digest)
    _digest(schema_digest)
    _text(signer_person_id, owner="kickoff signer")
    _require(
        type(allowed_paths) is tuple and 0 < len(allowed_paths) <= 256,
        "bounded exact kickoff path tuple required",
    )
    checked_paths = tuple(_text(path, owner="kickoff path") for path in allowed_paths)
    _require(
        len(allowed_paths) == len({path.casefold() for path in checked_paths}),
        "duplicate or case-alias kickoff path",
    )
    reserved_devices = {"con", "prn", "aux", "nul", "clock$", "conin$", "conout$"}
    reserved_devices.update(
        f"{prefix}{number}" for prefix in ("com", "lpt") for number in "0123456789⁰¹²³⁴⁵⁶⁷⁸⁹"
    )
    for path in checked_paths:
        _require(
            len(path) <= 512
            and not path.startswith("/")
            and not any(char in path for char in '\\:*?[]<>|"')
            and not any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in path)
            and all(
                part not in {"", ".", ".."}
                and part == part.rstrip(" .")
                and not part.startswith(" ")
                and part.split(".", 1)[0].rstrip(" ").casefold() not in reserved_devices
                for part in path.split("/")
            ),
            "kickoff paths must be confined portable file names",
        )
        _require(
            path.split("/", 1)[0].casefold()
            not in {".git", ".aws", ".claude", ".codex", ".agents"},
            "private or Git metadata cannot enter kickoff scope",
        )
    _require(
        set(work_limits)
        == {"maximum_changed_files", "maximum_diff_lines", "maximum_wall_clock_seconds"},
        "exact kickoff work limits required",
    )
    for limit in work_limits.values():
        _integer(limit, minimum=1)
    _require(
        len(allowed_paths) <= work_limits["maximum_changed_files"] <= 256,
        "file scope exceeds explicit bounded work profile",
    )
    scope = {
        "predecessor_closure_commit": PREDECESSOR_CLOSURE,
        "base_commit": base_commit,
        "allowed_paths": sorted(allowed_paths, key=lambda value: value.encode("utf-8")),
        "work_limits": dict(work_limits),
    }
    scoped_digest = content_digest(
        b"agent-assure:s1-successor-scope/v3\x00" + canonical_bytes(scope)
    )
    claim = {
        "format": "agent-assure-s1-successor-kickoff-claim/3",
        "acceptance_generation": 3,
        "receipt_purpose": "kickoff_authorization",
        "intended_effect": "bounded_corrective_development_only",
        "scope": scope,
        "scope_digest": scoped_digest,
        "policy_digest": policy_digest,
        "schema_digest": schema_digest,
        "requested_signer_person_id": signer_person_id,
        "requested_signer_role": "repository_maintainer",
        "required_competence_scope": "planning_governance:s1_successor",
        "permitted_operations": [
            "corrective_development",
            "governance_validation",
            "sprint2_design_preparation",
        ],
        "exclusions": [
            "no_method_admission",
            "no_independent_review_claim",
            "no_runtime_deployment_or_release_authorization",
            "no_retrospective_authorization",
        ],
        "signature_time_capability": "none",
        "trusted_import_observation_required_before_work": True,
    }
    payload = b"agent-assure:s1-successor-kickoff-signature/v3\x00" + canonical_bytes(claim)
    return claim, SigningRequest("s1-successor-kickoff/v3", payload, content_digest(payload))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SuccessorError(message)


def _time(value: object) -> datetime:
    _require(type(value) is str and _UTC.fullmatch(value) is not None, "strict UTC time required")
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SuccessorError("invalid UTC calendar time") from exc


def _now(value: datetime) -> datetime:
    _require(
        value.tzinfo is not None and value.utcoffset() == timedelta(0), "trusted UTC now required"
    )
    return value.astimezone(UTC)


def _text(value: object, *, owner: str) -> str:
    _require(type(value) is str and 0 < len(value) <= 4096, f"{owner}: bounded string required")
    return str(value)


def _digest(value: object) -> str:
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None, "SHA-256 digest required")
    return str(value)


def _oid(value: object) -> str:
    _require(
        type(value) is str and _OID.fullmatch(value) is not None, "full lowercase Git OID required"
    )
    return str(value)


def _integer(value: object, *, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, "strict integer required")
    return cast(int, value)


def _object(value: object, *, fields: set[str] | None = None) -> dict[str, Any]:
    _require(type(value) is dict, "closed JSON object required")
    result: dict[str, Any] = dict(cast(dict[str, Any], value))
    _require(all(type(key) is str for key in result), "string object keys required")
    if fields is not None:
        _require(set(result) == fields, "missing or extra object fields")
    return result


def _strings(value: object) -> tuple[str, ...]:
    _require(type(value) is list and len(value) <= 4096, "bounded string array required")
    rows = tuple(_text(item, owner="array item") for item in cast(list[Any], value))
    _require(len(rows) == len(set(rows)), "duplicate array identity")
    return rows


def _load_json(payload: bytes, *, canonical: bool) -> dict[str, Any]:
    _require(
        type(payload) is bytes and len(payload) <= 4 * 1024 * 1024, "bounded JSON bytes required"
    )

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            _require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    def reject_number(value: str) -> Any:
        raise SuccessorError(f"noninteger/nonfinite number is unsupported: {value[:20]}")

    try:
        value = _object(
            json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=pairs,
                parse_float=reject_number,
                parse_constant=reject_number,
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SuccessorError("invalid JSON evidence") from exc
    if canonical:
        _require(canonical_bytes(value) == payload, "evidence bytes are not canonical")
    return value


def _validate_policy(policy: SuccessorPolicy) -> None:
    _digest(policy.trust_snapshot_digest)
    _digest(policy.workflow_digest)
    _digest(policy.expected_validator_digest)
    _text(policy.signer_person_id, owner="policy signer")
    for values in (
        policy.required_ci_instances,
        policy.required_local_checks,
        policy.required_native_controls,
    ):
        _require(
            type(values) is tuple and 0 < len(values) <= 4096, "empty or oversized trusted policy"
        )
        _require(len(values) == len(set(values)), "duplicate trusted policy identity")
        for value in values:
            _text(value, owner="policy identity")
    _require(
        set(MANDATORY_CI_INSTANCES) <= set(policy.required_ci_instances),
        "trusted policy omits mandatory successor CI matrix instances",
    )
    _require(
        set(MANDATORY_LOCAL_CHECKS) <= set(policy.required_local_checks),
        "trusted policy omits mandatory successor local checks",
    )
    _require(
        set(MANDATORY_NATIVE_CONTROLS) <= set(policy.required_native_controls),
        "trusted policy omits mandatory successor native controls",
    )
    _require(type(policy.predecessor_tag_objects) is tuple, "immutable predecessor policy required")
    expected_names = {"agent-assure-s1-1.0.0a1-acceptance", "agent-assure-s1-1.0.0a1-acceptance-v2"}
    _require(len(policy.predecessor_tag_objects) == 2, "both immutable predecessor tags required")
    _require(
        {name for name, _ in policy.predecessor_tag_objects} == expected_names,
        "predecessor tag identity mismatch",
    )
    for _, oid in policy.predecessor_tag_objects:
        _oid(oid)
    _require(
        0 < _integer(policy.maximum_age_seconds) <= 30 * 86400, "invalid acceptance maximum age"
    )
    _require(
        0 < _integer(policy.finalization_window_seconds) <= 3600, "invalid finalization window"
    )


def _evidence(
    reference: str,
    kind: str,
    subject: str,
    now: datetime,
    boundary: TrustedSuccessorBoundary,
) -> dict[str, Any]:
    _digest(reference)
    evidence = boundary.resolve_evidence(reference, kind)
    _require(type(evidence) is VerifiedEvidence, "trusted verified evidence object required")
    _require(evidence_digest(evidence) == reference, "evidence digest substitution")
    return _evidence_document(evidence, kind, subject, now)


def _evidence_document(
    evidence: VerifiedEvidence,
    kind: str,
    subject: str,
    now: datetime,
) -> dict[str, Any]:
    _require(type(evidence) is VerifiedEvidence, "trusted verified evidence object required")
    document = _load_json(evidence.canonical_payload, canonical=True)
    fields = {"format", "kind", "subject_commit", "issued_at_utc", "valid_until_utc", "payload"}
    if "source_witness_digest" in document:
        fields.add("source_witness_digest")
        _digest(document["source_witness_digest"])
    _object(
        document,
        fields=fields,
    )
    _require(document["format"] == "agent-assure-s1-successor-evidence/3", "wrong evidence format")
    _require(
        document["kind"] == kind and document["subject_commit"] == subject,
        "evidence kind/subject substitution",
    )
    issued, expiry = _time(document["issued_at_utc"]), _time(document["valid_until_utc"])
    _require(issued <= now < expiry and issued < expiry, "future or expired evidence")
    return document


def _verify_identity(
    signature: VerifiedSignature,
    payload: bytes,
    policy: SuccessorPolicy,
    now: datetime,
    *,
    competence: str,
) -> None:
    _require(type(signature) is VerifiedSignature, "trusted signature result required")
    _require(signature.payload_sha256 == content_digest(payload), "signed-byte substitution")
    _require(
        signature.signer_person_id == policy.signer_person_id
        and signature.role == "repository_maintainer",
        "unassigned signature authority",
    )
    _require(competence in signature.competence_scopes, "missing signature competence scope")
    _require(
        signature.trust_snapshot_digest == policy.trust_snapshot_digest, "wrong trust snapshot"
    )
    verified = _time(signature.verification_completed_at_utc)
    _require(
        _time(signature.valid_from_utc) <= verified <= now < _time(signature.valid_until_utc),
        "signature authority is stale or future",
    )


def _check_receipt_shape(receipt: Mapping[str, Any]) -> dict[str, Any]:
    record = _object(dict(receipt), fields=_RECEIPT_FIELDS)
    _require(record["format"] == "agent-assure-s1-successor-acceptance/3", "wrong receipt format")
    _require(
        type(record["acceptance_generation"]) is int and record["acceptance_generation"] == 3,
        "wrong strict acceptance generation",
    )
    _require(
        _text(record["status"], owner="status")
        in {"pending_human_review", "accepted_for_development"},
        "wrong status",
    )
    _require(
        record["authorization_effect"] == "development_governance_only",
        "runtime authority forbidden",
    )
    _require(
        record["predecessor_closure_commit"] == PREDECESSOR_CLOSURE, "immutable predecessor changed"
    )
    for name in ("result_commit", "result_parent_commit"):
        _oid(record[name])
    for name in (
        *EVIDENCE_REFERENCE_FIELDS,
        "scope_digest",
        "kickoff_claim_digest",
        "receipt_digest",
    ):
        _digest(record[name])
    _require(
        record["clock_basis"] == "maintainer_host_utc_externally_unattested", "false clock claim"
    )
    _require(record["actual_signature_time_claimed"] is False, "SSHSIG has no signing timestamp")
    _time(record["issued_at_utc"])
    _time(record["valid_until_utc"])
    _require(record["receipt_digest"] == receipt_digest(record), "receipt digest mismatch")
    return record


def load_successor_receipt(payload: bytes) -> dict[str, Any]:
    """Strict duplicate-aware receipt loading; parsing conveys no acceptance."""
    return _check_receipt_shape(_load_json(payload, canonical=False))


def _validate_inputs(
    record: dict[str, Any],
    policy: SuccessorPolicy,
    now: datetime,
    boundary: TrustedSuccessorBoundary,
) -> None:
    _validate_policy(policy)
    issued, expiry = _time(record["issued_at_utc"]), _time(record["valid_until_utc"])
    _require(
        issued <= now < expiry and expiry - issued <= timedelta(seconds=policy.maximum_age_seconds),
        "receipt validity is stale, future, or excessive",
    )
    result = boundary.resolve_commit(record["result_commit"])
    _require(
        type(result) is GitCommit and result.oid == record["result_commit"], "result substitution"
    )
    _require(
        result.parents == (record["result_parent_commit"],), "result must be a nonmerge commit"
    )
    _require(result.oid not in result.parents, "cyclic result parent")
    _require(result.oid != PREDECESSOR_CLOSURE, "result must properly descend from C2")
    boundary.require_ancestor(PREDECESSOR_CLOSURE, result.oid)
    for name, expected_oid in policy.predecessor_tag_objects:
        tag = boundary.resolve_tag(name)
        _require(
            type(tag) is VerifiedTag and tag.object_oid == expected_oid,
            "immutable predecessor tag changed",
        )

    evidence: dict[str, dict[str, Any]] = {}
    for field, kind in EVIDENCE_REFERENCE_FIELDS.items():
        subject = PREDECESSOR_CLOSURE if kind == "prospective-kickoff" else result.oid
        evidence[kind] = _evidence(record[field], kind, subject, now, boundary)
        _require(
            _time(evidence[kind]["issued_at_utc"]) <= issued,
            "receipt predates prerequisite evidence",
        )
    payloads = {
        kind: _object(value["payload"], fields=_PAYLOAD_FIELDS[kind])
        for kind, value in evidence.items()
    }
    kickoff, observation = payloads["prospective-kickoff"], payloads["result-observation"]
    _require(
        kickoff.get("claim_digest") == record["kickoff_claim_digest"],
        "wrong prospective kickoff claim",
    )
    _require(kickoff.get("scope_digest") == record["scope_digest"], "kickoff scope substitution")
    _require(
        kickoff.get("policy_digest") == successor_policy_digest(policy),
        "prospective kickoff does not bind the exact verifier policy",
    )
    verified = _time(kickoff.get("signature_verification_completed_at_utc"))
    started, committed = (
        _time(observation.get("work_started_at_utc")),
        _time(observation.get("commit_observed_at_utc")),
    )
    _require(
        verified
        <= _time(evidence["prospective-kickoff"]["issued_at_utc"])
        < started
        <= committed
        <= _time(evidence["result-observation"]["issued_at_utc"])
        <= issued,
        "kickoff must be verified prospectively before result work",
    )
    _require(observation.get("scope_digest") == record["scope_digest"], "result scope substitution")
    allowed = _strings(observation.get("allowed_paths"))
    changed = _strings(observation.get("changed_paths"))
    _require(
        bool(changed) and set(changed) <= set(allowed),
        "result exceeds prospective exact file scope",
    )

    suite = payloads["native-full-suite-v4"]
    _require(
        suite.get("source_format") == "agent-assure-s1-post-r2-suite-evidence/4",
        "fresh v4 capture required",
    )
    _require(
        suite.get("kickoff_claim_digest") == record["kickoff_claim_digest"],
        "unbound v4 control-only capture",
    )
    _require(
        committed
        <= _time(suite.get("started_at_utc"))
        <= _time(suite.get("completed_at_utc"))
        <= _time(evidence["native-full-suite-v4"]["issued_at_utc"])
        <= issued,
        "native suite must be fresh after exact result",
    )
    _require(_integer(suite.get("exit_code")) == 0, "native suite failed")
    collected, passed, skipped = (
        _integer(suite.get(key)) for key in ("collected", "passed", "skipped")
    )
    _require(
        collected > 0 and passed > 0 and collected == passed + skipped,
        "incomplete terminal suite totals",
    )
    _require(
        all(_integer(suite.get(key)) == 0 for key in ("failed", "errors", "deselected")),
        "native suite not complete and passing",
    )
    _require(
        set(_strings(suite.get("control_ids"))) == set(policy.required_native_controls),
        "native control inventory mismatch",
    )
    _digest(suite.get("source_record_digest"))

    local = payloads["complete-local-checks"]
    checks = local.get("checks")
    _require(type(checks) is list and len(checks) <= 4096, "complete local check array required")
    seen: set[str] = set()
    for item in cast(list[Any], checks):
        check = _object(
            item, fields={"id", "started_at_utc", "completed_at_utc", "exit_code", "output_digest"}
        )
        identity = _text(check["id"], owner="local check")
        _require(identity not in seen, "duplicate local check")
        seen.add(identity)
        _require(_integer(check["exit_code"]) == 0, "local required check failed")
        _require(
            committed
            <= _time(check["started_at_utc"])
            <= _time(check["completed_at_utc"])
            <= _time(evidence["complete-local-checks"]["issued_at_utc"])
            <= issued,
            "local check not fresh for result",
        )
        _digest(check["output_digest"])
    _require(seen == set(policy.required_local_checks), "missing or extra required local checks")

    ci = payloads["hosted-ci"]
    _require(
        ci.get("repository") == "acblabs/agent-assure"
        and ci.get("workflow_path") == ".github/workflows/ci.yml",
        "wrong hosted CI source",
    )
    _require(
        ci.get("workflow_digest") == policy.workflow_digest and ci.get("head_sha") == result.oid,
        "CI workflow or subject substitution",
    )
    _text(ci.get("run_id"), owner="CI run")
    _integer(ci.get("run_attempt"), minimum=1)
    _require(
        ci.get("status") == "completed" and ci.get("conclusion") == "success",
        "CI run incomplete or failed",
    )
    jobs = ci.get("jobs")
    _require(type(jobs) is list and len(jobs) <= 4096, "complete CI matrix required")
    instances: set[str] = set()
    for item in cast(list[Any], jobs):
        job = _object(
            item,
            fields={"instance_id", "status", "conclusion", "started_at_utc", "completed_at_utc"},
        )
        identity = _text(job["instance_id"], owner="CI instance")
        _require(identity not in instances, "duplicate CI matrix instance")
        instances.add(identity)
        _require(
            job["status"] == "completed" and job["conclusion"] == "success",
            "CI instance skipped, cancelled, neutral, or unsuccessful",
        )
        _require(
            committed
            <= _time(job["started_at_utc"])
            <= _time(job["completed_at_utc"])
            <= _time(evidence["hosted-ci"]["issued_at_utc"])
            <= issued,
            "CI instance not fresh for result",
        )
    _require(
        instances == set(policy.required_ci_instances),
        "missing or extra hosted CI matrix instances",
    )

    roster = payloads["scoped-roster"]
    _require(roster.get("person_id") == policy.signer_person_id, "roster person substitution")
    _require(
        "planning_governance:s1_successor" in _strings(roster.get("competence_scopes"))
        and "schema_compatibility" in _strings(roster.get("competence_scopes")),
        "S2 roster competence missing",
    )
    _require(
        roster.get("mode") == "maintainer_development"
        and roster.get("independence") == "NO_INDEPENDENT_REVIEW",
        "unsupported independence or mode",
    )
    _require(
        bool(_strings(roster.get("conflicts")))
        and bool(_text(roster.get("review_capacity"), owner="review capacity")),
        "missing explicit conflicts or capacity",
    )
    forecast = payloads["fresh-forecast"]
    _require(
        forecast.get("baseline_commit") == result.oid
        and forecast.get("scope_digest") == record["scope_digest"],
        "forecast baseline/scope stale",
    )
    _require(
        forecast.get("disposition") == "human_accepted_after_dispatch_scope_rebaseline",
        "forecast decisions pending",
    )
    _digest(forecast.get("forecast_digest"))
    _digest(forecast.get("acceptance_receipt_digest"))
    key = payloads["scoped-signing-key"]
    _require(
        key.get("person_id") == policy.signer_person_id
        and key.get("trust_snapshot_digest") == policy.trust_snapshot_digest,
        "signing key authority substitution",
    )
    _require(
        {"s1_successor_governance", "s2_development_governance"}
        <= set(_strings(key.get("allowed_scopes"))),
        "S1-only key cannot accept S2",
    )


def prepare_successor_acceptance(
    *,
    result_commit: str,
    result_parent_commit: str,
    scope_digest: str,
    kickoff_claim_digest: str,
    evidence_references: Mapping[str, str],
    policy: SuccessorPolicy,
    boundary: TrustedSuccessorBoundary,
    now: datetime,
) -> dict[str, Any]:
    """Prepare exact review bytes after all authenticated prerequisites exist.

    Human acceptance is not supplied: status stays pending and signature null.
    Issue time is the caller's truthful observation time, not a signing time.
    """
    current = _now(now)
    _require(
        set(evidence_references) == set(EVIDENCE_REFERENCE_FIELDS),
        "exact evidence reference set required",
    )
    record: dict[str, Any] = {
        "format": "agent-assure-s1-successor-acceptance/3",
        "acceptance_generation": 3,
        "status": "pending_human_review",
        "authorization_effect": "development_governance_only",
        "predecessor_closure_commit": PREDECESSOR_CLOSURE,
        "result_commit": result_commit,
        "result_parent_commit": result_parent_commit,
        "scope_digest": scope_digest,
        "kickoff_claim_digest": kickoff_claim_digest,
        **dict(evidence_references),
        "issued_at_utc": current.isoformat().replace("+00:00", "Z"),
        "valid_until_utc": (current + timedelta(seconds=policy.maximum_age_seconds))
        .isoformat()
        .replace("+00:00", "Z"),
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "actual_signature_time_claimed": False,
        "signature_envelope": None,
    }
    record["receipt_digest"] = receipt_digest(record)
    checked = _check_receipt_shape(record)
    _validate_inputs(checked, policy, current, boundary)
    return checked


def accepted_signing_claim(pending: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Prepare the explicit human acceptance claim, without deciding or signing it.

    The returned template is not accepted until the trusted signature verifier
    succeeds. Editing the status changes the digest and exact signing bytes.
    """
    record = _check_receipt_shape(pending)
    _require(
        record["status"] == "pending_human_review" and record["signature_envelope"] is None,
        "untouched pending receipt required",
    )
    record["status"] = "accepted_for_development"
    record["receipt_digest"] = receipt_digest(record)
    return record, signature_claim(record)


def prepare_receipt_signing_request(
    pending: Mapping[str, Any],
) -> tuple[dict[str, Any], SigningRequest]:
    """Prepare explicit acceptance bytes for human review; acceptance stays pending.

    The returned record is an unsigned signing template with null envelope, not
    a schema-valid accepted receipt. Only subsequent scoped cryptographic
    verification by ``validate_successor_receipt`` can accept the signed record.
    """
    template, payload = accepted_signing_claim(pending)
    return template, SigningRequest("s1-successor-acceptance/v3", payload, content_digest(payload))


def validate_successor_receipt(
    receipt: Mapping[str, Any],
    *,
    policy: SuccessorPolicy,
    boundary: TrustedSuccessorBoundary,
    now: datetime,
) -> str:
    """Validate signed prerequisite receipt; alone it does not close S1 or start S2."""
    current = _now(now)
    record = _check_receipt_shape(receipt)
    _require(record["status"] == "accepted_for_development", "human acceptance is pending")
    envelope = _object(
        record["signature_envelope"],
        fields={"profile", "namespace", "signer_person_id", "key_id", "signature"},
    )
    _require(
        envelope["profile"] == SIGNATURE_PROFILE and envelope["namespace"] == SIGNATURE_NAMESPACE,
        "wrong signature profile or namespace",
    )
    for field in ("signer_person_id", "key_id", "signature"):
        _text(envelope[field], owner=field)
    _require(envelope["signer_person_id"] == policy.signer_person_id, "wrong envelope signer")
    _validate_inputs(record, policy, current, boundary)
    payload = signature_claim(record)
    verified = boundary.verify_signature(payload, envelope, "s1-successor-acceptance/v3")
    _verify_identity(
        verified, payload, policy, current, competence="planning_governance:s1_successor"
    )
    _require(
        _time(record["issued_at_utc"]) <= _time(verified.verification_completed_at_utc),
        "signature verification precedes claim preparation",
    )
    return str(record["receipt_digest"])


def validate_successor_subject(
    receipt: Mapping[str, Any],
    *,
    closure_commit: str,
    policy: SuccessorPolicy,
    boundary: TrustedSuccessorBoundary,
    now: datetime,
) -> ValidatedClosureSubject:
    """Verify the signed subject and original publication, without replay recursion.

    Fresh cryptographic verification proves current key control and exact bytes;
    its observation time is not the original publication time. The separately
    authenticated, countersigned publication source establishes that declared
    host observation. The first-publication/reuse command must also enforce its
    actual current clock before mutation; this replay API performs no mutation.
    """
    current = _now(now)
    digest = validate_successor_receipt(receipt, policy=policy, boundary=boundary, now=current)
    closure = boundary.resolve_commit(_oid(closure_commit))
    _require(
        type(closure) is GitCommit
        and closure.oid == closure_commit
        and closure.parents == (receipt["result_commit"],),
        "closure must be direct nonmerge child of R3",
    )
    _require(closure_commit != receipt["result_commit"], "cyclic closure parent")
    changed = boundary.changed_paths(str(receipt["result_commit"]), closure_commit)
    _require(
        type(changed) is tuple and changed == (RECEIPT_PATH,),
        "C3 may change only the signed successor receipt; tested R3 bytes must remain exact",
    )
    stored = boundary.read_commit_artifact(closure_commit, RECEIPT_PATH)
    _require(
        _load_json(stored, canonical=False) == dict(receipt),
        "C3 receipt bytes do not match supplied signed receipt",
    )
    tag = boundary.resolve_tag(SUCCESSOR_TAG)
    _require(
        type(tag) is VerifiedTag and tag.target_commit == closure_commit,
        "fixed v3 tag targets another closure",
    )
    _oid(tag.object_oid)
    _require(type(tag.signature) is VerifiedSignature, "successor tag signature is unverified")
    tag_signature = cast(VerifiedSignature, tag.signature)
    claim = _load_json(tag.canonical_claim, canonical=True)
    _object(
        claim,
        fields={
            "format",
            "acceptance_generation",
            "predecessor_closure_commit",
            "result_commit",
            "closure_commit",
            "receipt_path",
            "receipt_sha256",
            "receipt_digest",
            "prepared_at_utc",
            "finalize_by_utc",
        },
    )
    _require(
        claim["format"] == "agent-assure-s1-current-acceptance-attestation/3"
        and type(claim["acceptance_generation"]) is int
        and claim["acceptance_generation"] == 3,
        "wrong successor tag attestation",
    )
    expected = {
        "predecessor_closure_commit": PREDECESSOR_CLOSURE,
        "result_commit": receipt["result_commit"],
        "closure_commit": closure_commit,
        "receipt_path": RECEIPT_PATH,
        "receipt_sha256": content_digest(stored),
        "receipt_digest": digest,
    }
    _require(
        all(claim[key] == value for key, value in expected.items()),
        "tag/closure/receipt binding mismatch",
    )
    prepared, deadline = _time(claim["prepared_at_utc"]), _time(claim["finalize_by_utc"])
    _require(
        _time(receipt["issued_at_utc"]) <= prepared < deadline <= _time(receipt["valid_until_utc"])
        and deadline - prepared <= timedelta(seconds=policy.finalization_window_seconds),
        "invalid fixed-tag finalization window",
    )
    _verify_identity(
        tag_signature,
        tag.canonical_claim,
        policy,
        current,
        competence="planning_governance:s1_successor",
    )
    publication_source = boundary.resolve_publication(tag)
    publication = _evidence_document(
        publication_source, "fixed-tag-publication", closure_commit, current
    )
    publication_payload = _object(
        publication["payload"],
        fields={
            "tag_object",
            "closure_commit",
            "tag_claim_sha256",
            "receipt_sha256",
            "published_at_utc",
            "readback_completed_at_utc",
            "clock_basis",
            "actual_signature_time_claimed",
        },
    )
    _require(
        publication_payload["tag_object"] == tag.object_oid
        and publication_payload["closure_commit"] == closure_commit
        and publication_payload["tag_claim_sha256"] == content_digest(tag.canonical_claim)
        and publication_payload["receipt_sha256"] == content_digest(stored),
        "publication observation subject substitution",
    )
    _require(
        publication_payload["clock_basis"] == "maintainer_host_utc_externally_unattested"
        and publication_payload["actual_signature_time_claimed"] is False,
        "publication cannot invent signing time or independent clock provenance",
    )
    published = _time(publication_payload["published_at_utc"])
    readback = _time(publication_payload["readback_completed_at_utc"])
    _require(
        prepared <= published <= readback < deadline
        and readback <= _time(publication["issued_at_utc"]),
        "original publication/read-back was outside the signed finalization window",
    )
    return ValidatedClosureSubject(
        str(receipt["result_commit"]),
        closure_commit,
        digest,
        content_digest(stored),
        tag.object_oid,
        evidence_digest(publication_source),
        str(publication_payload["published_at_utc"]),
        str(publication_payload["readback_completed_at_utc"]),
    )


def validate_successor_closure(
    receipt: Mapping[str, Any],
    *,
    closure_commit: str,
    historical_replay_digest: str,
    policy: SuccessorPolicy,
    boundary: TrustedSuccessorBoundary,
    now: datetime,
) -> AcceptedSuccessor:
    """Close only after subject validation and a separate real standalone replay."""
    current = _now(now)
    subject = validate_successor_subject(
        receipt, closure_commit=closure_commit, policy=policy, boundary=boundary, now=current
    )
    history = _evidence(
        historical_replay_digest, "standalone-historical-replay", closure_commit, current, boundary
    )
    proof = _object(
        history["payload"],
        fields={
            "tag_object",
            "receipt_sha256",
            "mode",
            "exit_code",
            "started_at_utc",
            "completed_at_utc",
            "validator_digest",
            "publication_evidence_digest",
        },
    )
    _require(
        proof["tag_object"] == subject.fixed_tag_object
        and proof["receipt_sha256"] == subject.receipt_sha256
        and proof["publication_evidence_digest"] == subject.publication_evidence_digest,
        "historical replay subject substitution",
    )
    _require(
        proof["mode"] == "standalone_clone_no_local" and _integer(proof["exit_code"]) == 0,
        "standalone historical replay missing or failed",
    )
    _require(
        _time(subject.readback_completed_at_utc)
        <= _time(proof["started_at_utc"])
        <= _time(proof["completed_at_utc"])
        <= _time(history["issued_at_utc"]),
        "historical replay must follow authenticated publication read-back",
    )
    _require(
        _digest(proof["validator_digest"]) == policy.expected_validator_digest,
        "historical replay used an unpinned validator",
    )
    return AcceptedSuccessor(
        str(receipt["result_commit"]),
        closure_commit,
        subject.receipt_digest,
        subject.fixed_tag_object,
        historical_replay_digest,
        publication_evidence_digest=subject.publication_evidence_digest,
    )
