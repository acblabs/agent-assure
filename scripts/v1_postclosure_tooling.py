"""Verify an exact post-closure overlay under externally authenticated inputs.

This is deliberately not a trust bootstrap or an accepting command-line tool.
The operator must authenticate this module, its dependency closure, runtime,
GitReader, enrolled keys, verifier and clock before calling ``verify``. Neither
an amendment nor a repository-local success flag supplies those inputs.
Historical Git objects are read as data; no historical Python is imported.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from scripts import v1_architecture_governance as architecture
from scripts import v1_correction_acceptance as acceptance
from scripts import v1_governance_corrections as corrections
from scripts import v1_s1_successor as successor_core
from scripts import v1_successor_io as io

DIRECTORY = "docs/governance/v1/sprint3"
AMENDMENT_PATH = f"{DIRECTORY}/post-closure-tooling-amendment.json"
SCHEMA_PATH = f"{DIRECTORY}/post-closure-tooling-amendment.schema.json"
PURPOSE = "post-closure-tooling-amendment/v1"
CLAIM_DOMAIN = b"agent-assure:post-closure-tooling-amendment/v1\x00"
HISTORICAL_SOURCE = "3a85cf19a9e71fc658d70ceee904ab9f7811d716"
PUBLISHED_EVIDENCE = "9e9fc9937b1a5436343ced8fdac47ccbde379d4a"
SOURCE_DIGEST = "sha256:1b9dabb7e106a747cca840e929984afaac6c831f74422bd0f95a42e2dce9faa2"
RECEIPT_DIGEST = "sha256:5a183239b199fdb4f9ca19e00754b7208f304970462a02bca5cab9f61ca59d21"
S1_CLOSURE = "20a49c9c6c57ffa6096f5db9a466b472d7bc54fb"
S1_TAG_OBJECT = "9f57de66e57a18a74a154524841dd055fe26a090"
S1_TAG = "agent-assure-s1-1.0.0a1-acceptance-v3"
EXPIRY = "2026-12-07T23:31:10.233520Z"
CI_PATH = ".github/workflows/ci.yml"
CI_PREDECESSOR = {
    "path": CI_PATH,
    "size_bytes": 24441,
    "sha256": "sha256:39d77676060b1f068121e1100a0d56ae627da6877e1f81e051902c264d72579a",
}
CI_REVIEWED = {
    "path": CI_PATH,
    "size_bytes": 24730,
    "sha256": "sha256:2fc01b56a9300974f32ece60d38a1ba48643ca4898f356e6e62cc5d0e4a0b84c",
}
ROOT_PERSON = "acblabs"
ROOT_KEY_ID = "SHA256:L/6IRITdktnUQOfbr6iuf48k2MtolzDFvxWaQHU4G7k"
ROOT_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7Bgeqxj82OCpkAsF4Qzby2m5PfOnh4lNKzl3fXZ/uB"
MAX_FILES = 128
MAX_TOTAL_BYTES = 16 * 1024**2
_OID = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z")

# This finite source vocabulary is implementation-owned, never learned from a
# submitted claim. The independently authenticated expected claim fixes hashes.
NEW_FILES = (
    SCHEMA_PATH,
    "scripts/v1_postclosure_tooling.py",
    "tests/unit/governance/test_v1_postclosure_tooling.py",
)
MODIFIABLE_HISTORICAL_FILES = frozenset(
    {
        ".github/workflows/ci.yml",
        "scripts/v1_architecture_governance.py",
        "tests/unit/governance/test_v1_governance_corrections.py",
    }
)
DEPENDENCY_FILES = (
    "src/agent_assure/io_limits.py",
    "src/agent_assure/rooted_io.py",
)
PUBLIC_DIRECTORY = "docs/governance/v1/sprint2"
PUBLIC_MANIFEST = f"{PUBLIC_DIRECTORY}/correction-export-manifest.json"
PUBLIC_RECEIPT = f"{PUBLIC_DIRECTORY}/correction-acceptance.json"
S1_RECEIPT = f"{PUBLIC_DIRECTORY}/s1-successor-acceptance.json"
S1_RECEIPT_DIGEST = "sha256:c6e9bb393a87bad7c389ff16a66169961e4daf3d9111ae65e5853d4158e4f586"
HISTORICAL_PURPOSES = (
    "sprint12-scoped-authority-adoption/v1",
    "s1-successor-acceptance/v3",
    "s2-drafting/v1",
    "s2-design-acceptance/v1",
    "s2-bundle/v1",
)
PUBLIC_FILES = (
    f"{PUBLIC_DIRECTORY}/closure-status.md",
    PUBLIC_RECEIPT,
    f"{PUBLIC_DIRECTORY}/correction-native-verification.json",
    f"{PUBLIC_DIRECTORY}/correction-review-request.json",
    f"{PUBLIC_DIRECTORY}/correction-subjects/forecast-acceptance.json",
    f"{PUBLIC_DIRECTORY}/correction-subjects/foundation-adoption.json",
    f"{PUBLIC_DIRECTORY}/correction-subjects/support-policy-adoption.json",
    f"{PUBLIC_DIRECTORY}/delivery-forecast.accepted-v4.json",
    f"{PUBLIC_DIRECTORY}/predecessor-signed-components-v3.json",
)
SUBJECT_PATHS = {
    "foundation_adoption": f"{PUBLIC_DIRECTORY}/correction-subjects/foundation-adoption.json",
    "forecast_producer": f"{PUBLIC_DIRECTORY}/delivery-forecast.accepted-v4.json",
    "forecast_acceptance": f"{PUBLIC_DIRECTORY}/correction-subjects/forecast-acceptance.json",
    "design_amendment": "docs/adr/0023-v1-governance-closure-corrections.md",
    "support_policy": f"{PUBLIC_DIRECTORY}/correction-subjects/support-policy-adoption.json",
}
RETAINED_CONSTRAINTS = {
    "original_authoring_guard_unchanged": True,
    "accepted_subject_bytes_and_fixed_tags_unchanged": True,
    "retained_original_host_replay_claimed": False,
    "complete_portable_private_predecessor_replay_claimed": False,
    "all_unlisted_current_tooling_changes_rejected": True,
    "no_source_normalization_or_network_fallback": True,
    "implementation_or_qualification_acceptance_granted": False,
    "merge_release_publication_or_deployment_authorized": False,
}


class ImmutableReader(Protocol):
    """The existing authenticated GitReader implements this bounded vocabulary."""

    def read_commit_artifact(self, commit: str, path: str) -> bytes: ...

    def resolve_commit(self, oid: str) -> Any: ...

    def require_ancestor(self, ancestor: str, descendant: str) -> None: ...

    def changed_paths(self, base_commit: str, target_commit: str) -> tuple[str, ...]: ...

    def read_annotated_tag(self, name: str) -> io.AnnotatedTag: ...


@dataclass(frozen=True)
class AuthenticatedInputs:
    """Only the independently authenticated operator may construct these.

    ``expected_claim`` is canonical claim JSON frozen in that operator's signed
    input packet, not read from the submitted amendment. Keys and callbacks
    must likewise come from that packet's authenticated trust/runtime boundary.
    The current commit ID is observed by the operator, never a mutable ref here.
    """

    expected_claim: bytes
    root_key: io.TrustedKey
    historical_root_key: io.TrustedKey
    git: ImmutableReader
    verify_signature: io.SSHVerifier
    now: Callable[[], datetime]
    runtime_profile_digest: str
    receipt_publication_commit: str
    current_commit: str


@dataclass(frozen=True)
class PostclosureVerification:
    source_root: Path
    current_commit: str
    amendment_claim_digest: str
    current_inventory_digest: str
    predecessor_package_digest: str = corrections.PREDECESSOR_PACKAGE_DIGEST
    historical_source_bindings_digest: str = SOURCE_DIGEST
    accepted_sprint12_receipt_digest: str = RECEIPT_DIGEST
    published_historical_receipt_signatures_and_source_bindings_verified: bool = True
    exact_postclosure_tooling_overlay_verified: bool = True
    retained_original_host_replay_performed: bool = False
    authorization_effect: str = "historical_and_exact_current_tooling_development_verification_only"


def _require(value: bool, message: str) -> None:
    if not value:
        raise architecture.ArchitectureError(message)


def _time(value: object) -> datetime:
    _require(type(value) is str and _UTC.fullmatch(value) is not None, "strict UTC time required")
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise architecture.ArchitectureError("invalid UTC time") from exc


def _clock(now: Callable[[], datetime]) -> datetime:
    value = now()
    _require(
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() == UTC.utcoffset(value),
        "UTC verification clock required",
    )
    return value


def _oid(value: object) -> str:
    _require(
        type(value) is str and _OID.fullmatch(value) is not None,
        "immutable full commit ID required",
    )
    return str(value)


def _path(value: object) -> str:
    _require(type(value) is str and 0 < len(value) <= 512, "bounded source path required")
    text = str(value)
    _require(
        all(part not in {"", ".", ".."} for part in text.split("/"))
        and "\\" not in text
        and not any(ord(c) < 32 or c in ':<>"|?*' for c in text),
        "noncanonical source path",
    )
    return text


def _rows(value: Any) -> list[dict[str, Any]]:
    _require(
        type(value) is list and 0 < len(value) <= MAX_FILES, "bounded exact inventory required"
    )
    rows: list[dict[str, Any]] = []
    for row in value:
        _require(
            type(row) is dict and set(row) == {"path", "sha256", "size_bytes"},
            "closed source binding required",
        )
        _path(row["path"])
        _require(
            type(row["sha256"]) is str and _DIGEST.fullmatch(row["sha256"]) is not None,
            "exact source digest required",
        )
        _require(
            type(row["size_bytes"]) is int
            and 0 <= row["size_bytes"] <= architecture.MAX_ARTIFACT_BYTES,
            "bounded source size required",
        )
        rows.append(row)
    paths = [row["path"] for row in rows]
    _require(paths == sorted(set(paths)), "inventory is duplicated, reordered or noncanonical")
    _require(
        len({path.casefold() for path in paths}) == len(paths), "case-colliding inventory paths"
    )
    _require(
        sum(row["size_bytes"] for row in rows) <= MAX_TOTAL_BYTES,
        "inventory exceeds aggregate byte limit",
    )
    return rows


def historical_source_paths() -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                *("docs/governance/v1/" + name for name in architecture.HISTORICAL_FILES),
                *(values[1] for values in architecture.DECISIONS.values()),
                *architecture.SUPPLEMENTARY,
                *architecture.TOOLING,
                *corrections.ADDED,
                *corrections.REPLACED,
                *DEPENDENCY_FILES,
                f"{PUBLIC_DIRECTORY}/architecture-package.json",
                corrections.SOURCE_BINDINGS,
                S1_RECEIPT,
                ".github/CODEOWNERS",
                "SECURITY.md",
            }
        )
    )


def current_source_paths() -> tuple[str, ...]:
    return tuple(sorted({*historical_source_paths(), *NEW_FILES, PUBLIC_MANIFEST, *PUBLIC_FILES}))


def binding(path: str, data: bytes) -> dict[str, Any]:
    _path(path)
    _require(
        type(data) is bytes and len(data) <= architecture.MAX_ARTIFACT_BYTES,
        "bounded source bytes required",
    )
    return {"path": path, "size_bytes": len(data), "sha256": architecture.raw_digest(data)}


def _snapshot(reader: ImmutableReader, commit: str, rows: list[dict[str, Any]]) -> dict[str, bytes]:
    _oid(commit)
    result: dict[str, bytes] = {}
    for row in rows:
        data = reader.read_commit_artifact(commit, row["path"])
        _require(
            binding(row["path"], data) == row,
            "immutable historical or reviewed source blob differs",
        )
        result[row["path"]] = data
    return result


def _current(root: Path, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        _require(
            architecture.artifact(root, row["path"]) == row,
            "current source differs from exact reviewed inventory",
        )


def _verify_historical_sources(files: Mapping[str, bytes]) -> None:
    """Recompute the accepted source-binding projection using data only."""
    package = architecture.parse_json(files[f"{PUBLIC_DIRECTORY}/architecture-package.json"])
    projection = {key: value for key, value in package.items() if key != "package_digest"}
    _require(
        package["package_digest"]
        == corrections.PREDECESSOR_PACKAGE_DIGEST
        == architecture.domain_digest("agent-assure:v1-architecture-package/v1", projection),
        "immutable predecessor package differs",
    )
    record = architecture.parse_json(files[corrections.SOURCE_BINDINGS])
    record_projection = {key: value for key, value in record.items() if key != "record_digest"}
    _require(
        record["record_digest"]
        == SOURCE_DIGEST
        == architecture.domain_digest(
            "agent-assure:sprint12-source-bindings/v1", record_projection
        ),
        "historical correction source-binding digest differs",
    )
    # The old package intentionally contains its predecessor tooling bytes.
    # Accepted replacement rows alone select its corrected historical tooling.
    replacements = record["replacements"]
    _require(
        type(replacements) is list and len(replacements) <= len(corrections.REPLACED),
        "invalid historical replacement list",
    )
    by_path = {row["path"]: row for row in replacements}
    _require(
        len(by_path) == len(replacements) and set(by_path) <= corrections.REPLACED,
        "unapproved historical replacement",
    )
    for row in package["tooling_artifacts"]:
        replacement = by_path.get(row["path"])
        if replacement is not None:
            _require(replacement["predecessor"] == row, "historical predecessor tooling mismatch")
            row = replacement["current"]
        _require(binding(row["path"], files[row["path"]]) == row, "historical tooling bytes differ")
    for row in [
        *(item["artifact"] for item in package["decisions"]),
        *package["historical_artifacts"],
        *package["supplementary_artifacts"],
        *record["added_artifacts"],
        *record["external_dependencies"],
    ]:
        _require(
            binding(row["path"], files[row["path"]]) == row,
            "historical signed or source-bound artifact differs",
        )
    _require(
        [row["path"] for row in record["added_artifacts"]] == list(corrections.ADDED)
        and record["format"] == "agent-assure-sprint12-correction-source-bindings/1"
        and record["status"] == "prepared_for_human_review"
        and record["authorization_effect"] == "none"
        and record["predecessor_package_digest"] == corrections.PREDECESSOR_PACKAGE_DIGEST,
        "historical source projection differs",
    )


def _verify_public_receipt(files: Mapping[str, bytes], inputs: AuthenticatedInputs) -> None:
    receipt = architecture.parse_json(files[PUBLIC_RECEIPT])
    _require(
        receipt["receipt_digest"]
        == RECEIPT_DIGEST
        == architecture.domain_digest(
            "agent-assure:sprint12-correction-acceptance/v1",
            {key: value for key, value in receipt.items() if key != "receipt_digest"},
        ),
        "accepted Sprint 1/2 receipt differs",
    )
    _require(
        receipt["implementation_commit"] == HISTORICAL_SOURCE
        and receipt["source_bindings_digest"] == SOURCE_DIGEST,
        "accepted receipt source differs",
    )
    authority = receipt["authority_document"]
    claim = authority["claim"]
    _require(
        claim["purpose"] == "sprint12-scoped-authority-adoption/v1"
        and claim["implementation_commit"] == HISTORICAL_SOURCE
        and claim["source_bindings_digest"] == SOURCE_DIGEST,
        "historical authority adoption differs",
    )
    io.verify(
        b"agent-assure:sprint12-authority-adoption/v1\x00" + successor_core.canonical_bytes(claim),
        authority["signature_envelope"],
        inputs.historical_root_key,
        inputs.verify_signature,
        now=inputs.now,
        purpose="sprint12-scoped-authority-adoption/v1",
    )
    authorities: dict[str, io.TrustedKey] = {}
    for role, adopted in claim["roles"].items():
        _require(
            adopted["person_id"] == ROOT_PERSON
            and adopted["public_key"] == ROOT_PUBLIC_KEY
            and adopted["key_id"] == ROOT_KEY_ID
            and adopted["role"] == role,
            "historical adopted root substitution",
        )
        authorities[role] = replace(
            inputs.historical_root_key,
            role=role,
            competence_scopes=tuple(adopted["competence_scopes"]),
            allowed_purposes=tuple(adopted["allowed_purposes"]),
            trust_snapshot_digest=architecture.raw_digest(
                b"agent-assure:sprint12-authority-adoption/v1\x00"
                + successor_core.canonical_bytes(claim)
            ),
            valid_from_utc=adopted["valid_from_utc"],
            valid_until_utc=adopted["valid_until_utc"],
        )
    # Expected claims are extracted only after the entire receipt has matched
    # the independently fixed accepted digest and its authority is verified.
    documents = receipt["signed_decisions"]
    acceptance.verify_correction_acceptance(
        documents,
        {name: document["claim"] for name, document in documents.items()},
        authorities,
        inputs.verify_signature,
        now=inputs.now,
        prerequisite_valid_until_utc=EXPIRY,
    )
    for name, path in SUBJECT_PATHS.items():
        _require(
            architecture.raw_digest(files[path]) == documents[name]["claim"]["subject_digest"],
            "published signed subject differs",
        )


def _verify_predecessor_public_signatures(
    historical: Mapping[str, bytes],
    published: Mapping[str, bytes],
    inputs: AuthenticatedInputs,
) -> None:
    """Refresh portable public signatures without claiming original-host replay."""
    core = successor_core
    receipt = architecture.parse_json(historical[S1_RECEIPT])
    _require(
        receipt["receipt_digest"] == S1_RECEIPT_DIGEST == core.receipt_digest(receipt),
        "original generation-3 receipt differs",
    )
    _require(
        receipt["status"] == "accepted_for_development"
        and receipt["authorization_effect"] == "development_governance_only"
        and receipt["valid_until_utc"] == EXPIRY,
        "original generation-3 acceptance boundary differs",
    )
    io.verify(
        core.signature_claim(receipt),
        receipt["signature_envelope"],
        inputs.historical_root_key,
        inputs.verify_signature,
        now=inputs.now,
        purpose="s1-successor-acceptance/v3",
    )
    components = architecture.parse_json(
        published[f"{PUBLIC_DIRECTORY}/predecessor-signed-components-v3.json"]
    )
    _require(
        components["format"] == "agent-assure-s2-signed-components-view/1"
        and components["complete_trusted_replay_requires_retained_full_inputs_and_original_host"]
        is True,
        "public component view must retain its replay limitation",
    )
    decisions = components["decisions"]
    _require(
        type(decisions) is list and len(decisions) == 14,
        "exact fourteen S2 decision records required",
    )
    domain = b"agent-assure:s1-successor-human-decision/v3\x00"
    expected_subjects = []
    for ticket, values in architecture.DECISIONS.items():
        expected_subjects.extend(
            [
                (ticket, values[0], values[1], "s2-drafting/v1"),
                (ticket, values[0], values[1], "s2-design-acceptance/v1"),
            ]
        )
    expected_subjects.extend(
        [
            (
                "V1-BASE-06",
                "POLICY-V1-SUPPORT",
                f"{PUBLIC_DIRECTORY}/support-policy.json",
                "s2-design-acceptance/v1",
            ),
            (
                "V1-BASE-02",
                "PRODUCT-INCONCLUSIVE-01",
                "docs/adr/0017-v1-evidence-temporal-semantics.md",
                "s2-design-acceptance/v1",
            ),
        ]
    )
    digests: list[str] = []
    for index, (document, (ticket, identifier, path, purpose)) in enumerate(
        zip(decisions, expected_subjects, strict=True)
    ):
        _require(
            type(document) is dict and set(document) == {"claim", "signature_envelope"},
            "closed historical decision document required",
        )
        claim = document["claim"]
        _require(
            (claim["ticket_id"], claim["decision_id"], claim["subject_path"], claim["purpose"])
            == (ticket, identifier, path, purpose)
            and claim["subject_sha256"] == architecture.raw_digest(historical[path])
            and claim["authorization_effect"] == "development_governance_only",
            "historical decision subject, purpose or order differs",
        )
        if index < 12 and index % 2 == 1:
            _require(
                claim["start_claim_digest"] == digests[-1]
                and claim["method_or_profile_admission"] is False
                and claim["qualified_review_pending"] is True,
                "historical design acceptance boundary differs",
            )
        payload = domain + core.canonical_bytes(claim)
        io.verify(
            payload,
            document["signature_envelope"],
            inputs.historical_root_key,
            inputs.verify_signature,
            now=inputs.now,
            purpose=purpose,
        )
        digests.append(architecture.raw_digest(payload))
    bundle = components["bundle"]
    claim = bundle["claim"]
    _require(
        claim["purpose"] == "s2-bundle/v1"
        and claim["architecture_package_digest"] == corrections.PREDECESSOR_PACKAGE_DIGEST
        and claim["decision_claim_digests"] == digests
        and claim["successor_basis"]["receipt_digest"] == S1_RECEIPT_DIGEST
        and claim["successor_basis"]["closure_commit"] == S1_CLOSURE
        and claim["successor_basis"]["fixed_tag_object"] == S1_TAG_OBJECT
        and claim["authorization_effect"] == "development_governance_only",
        "aggregate historical S2 closure differs",
    )
    io.verify(
        domain + core.canonical_bytes(claim),
        bundle["signature_envelope"],
        inputs.historical_root_key,
        inputs.verify_signature,
        now=inputs.now,
        purpose="s2-bundle/v1",
    )


def verify(root: Path, *, inputs: AuthenticatedInputs) -> PostclosureVerification:
    """Verify the historical proof and exact current overlay, without authority escalation.

    Operator integration: authenticate the complete implementation and runtime
    first; construct ``AuthenticatedInputs`` from that independently signed
    packet; pass ``lambda root: verify(root, inputs=inputs)`` to
    ``architecture.check_package(..., postclosure_verifier=...)``. Ordinary CLI
    invocation intentionally has no accepting fallback.
    """
    _require(
        type(inputs) is AuthenticatedInputs
        and callable(inputs.now)
        and callable(inputs.verify_signature),
        "externally authenticated inputs required",
    )
    expected = architecture.parse_json(inputs.expected_claim)
    _require(
        successor_core.canonical_bytes(expected) == inputs.expected_claim,
        "independently pinned claim must use canonical bytes",
    )
    document_raw = architecture.read_bytes(root, AMENDMENT_PATH, architecture.MAX_JSON_BYTES)
    document = architecture.parse_json(document_raw)
    _require(
        set(document) == {"claim", "signature_envelope"}
        and successor_core.canonical_bytes(document["claim"]) == inputs.expected_claim,
        "amendment differs from independently reviewed exact claim",
    )
    fixed = {
        "format": "agent-assure-post-closure-tooling-amendment/1",
        "purpose": PURPOSE,
        "decision": "adopt_exact_current_tooling_overlay_and_historical_verification_route",
        "issuer_person_id": ROOT_PERSON,
        "issuer_role": "repository_maintainer",
        "key_id": ROOT_KEY_ID,
        "approval_mode": "maintainer_development",
        "independence": "NO_INDEPENDENT_REVIEW",
        "authorization_effect": (
            "historical_and_exact_current_tooling_development_verification_only"
        ),
        "historical_source_commit": HISTORICAL_SOURCE,
        "published_correction_evidence_commit": PUBLISHED_EVIDENCE,
        "accepted_sprint12_receipt_digest": RECEIPT_DIGEST,
        "historical_source_bindings_digest": SOURCE_DIGEST,
        "historical_predecessor_package_digest": corrections.PREDECESSOR_PACKAGE_DIGEST,
        "s1_v3_closure_commit": S1_CLOSURE,
        "s1_v3_fixed_tag_object": S1_TAG_OBJECT,
        "receipt_publication_topology": (
            "receipt_only_direct_child_of_reviewed_implementation_commit"
        ),
        "authority_record_path": AMENDMENT_PATH,
        "valid_until_utc": EXPIRY,
        "retained_constraints": RETAINED_CONSTRAINTS,
    }
    variable = {
        "issued_at_utc",
        "reviewed_implementation_source_commit",
        "historical_source_inventory",
        "published_evidence_inventory",
        "reviewed_current_inventory",
        "current_tooling_overlay",
        "external_runtime_profile_digest",
        "key_scope_adoption",
    }
    _require(
        set(expected) == set(fixed) | variable
        and successor_core.canonical_bytes({key: expected[key] for key in fixed})
        == successor_core.canonical_bytes(fixed),
        "closed amendment identity, scope or constraints differ",
    )
    for key in (inputs.root_key, inputs.historical_root_key):
        _require(
            type(key) is io.TrustedKey
            and key.person_id == ROOT_PERSON
            and key.key_id == ROOT_KEY_ID
            and key.public_key == ROOT_PUBLIC_KEY,
            "independently enrolled root identity required",
        )
    _require(
        set(HISTORICAL_PURPOSES) <= set(inputs.historical_root_key.allowed_purposes),
        "all historical verification purposes require independently adopted scope",
    )
    _require(
        inputs.root_key.role == "repository_maintainer"
        and PURPOSE in inputs.root_key.allowed_purposes
        and expected["key_scope_adoption"]
        == {"purpose": PURPOSE, "trust_snapshot_digest": inputs.root_key.trust_snapshot_digest},
        "exact new key-purpose adoption required",
    )
    _require(
        type(inputs.runtime_profile_digest) is str
        and _DIGEST.fullmatch(inputs.runtime_profile_digest) is not None
        and expected["external_runtime_profile_digest"] == inputs.runtime_profile_digest,
        "external runtime profile differs",
    )
    started = _clock(inputs.now)
    _require(
        _time(inputs.root_key.valid_from_utc)
        <= _time(expected["issued_at_utc"])
        <= started
        < _time(EXPIRY)
        <= _time(inputs.root_key.valid_until_utc),
        "amendment is future, expired or extends adopted authority",
    )
    observed = started

    def checked_now() -> datetime:
        nonlocal observed
        current = _clock(inputs.now)
        _require(observed <= current < _time(EXPIRY), "amendment expired or clock regressed")
        observed = current
        return current

    checked_inputs = replace(inputs, now=checked_now)
    io.verify(
        CLAIM_DOMAIN + inputs.expected_claim,
        document["signature_envelope"],
        inputs.root_key,
        inputs.verify_signature,
        now=checked_now,
        purpose=PURPOSE,
    )
    historical_rows = _rows(expected["historical_source_inventory"])
    public_rows = _rows(expected["published_evidence_inventory"])
    current_rows = _rows(expected["reviewed_current_inventory"])
    _require(
        tuple(row["path"] for row in historical_rows) == historical_source_paths(),
        "complete historical source vocabulary required",
    )
    _require(
        tuple(row["path"] for row in public_rows)
        == tuple(sorted({PUBLIC_MANIFEST, *PUBLIC_FILES})),
        "complete published evidence vocabulary required",
    )
    _require(
        tuple(row["path"] for row in current_rows) == current_source_paths(),
        "complete exact current source vocabulary required",
    )
    _require(
        next(row for row in historical_rows if row["path"] == CI_PATH) == CI_PREDECESSOR
        and next(row for row in current_rows if row["path"] == CI_PATH) == CI_REVIEWED,
        "only the exact approved six-line CI extension is admitted",
    )
    historical = _snapshot(inputs.git, HISTORICAL_SOURCE, historical_rows)
    _verify_historical_sources(historical)
    published = _snapshot(inputs.git, PUBLISHED_EVIDENCE, public_rows)
    published.update(
        {path: historical[path] for path in SUBJECT_PATHS.values() if path not in published}
    )
    manifest = architecture.parse_json(published[PUBLIC_MANIFEST])
    _require(
        manifest["accepted_receipt_digest"] == RECEIPT_DIGEST
        and len(manifest["files"]) == len(PUBLIC_FILES)
        and {row["path"] for row in manifest["files"]} == set(PUBLIC_FILES),
        "public export inventory differs",
    )
    for row in manifest["files"]:
        _require(binding(row["path"], published[row["path"]]) == row, "public export bytes differ")
    _verify_public_receipt(published, checked_inputs)
    _verify_predecessor_public_signatures(historical, published, checked_inputs)
    tag = inputs.git.read_annotated_tag(S1_TAG)
    _require(
        tag.object_oid == S1_TAG_OBJECT and tag.target_commit == S1_CLOSURE,
        "fixed historical tag changed",
    )
    implementation = _oid(expected["reviewed_implementation_source_commit"])
    publication = _oid(inputs.receipt_publication_commit)
    current = _oid(inputs.current_commit)
    _require(
        inputs.git.resolve_commit(publication).parents == (implementation,),
        "receipt publication must be a nonmerge direct child",
    )
    _require(
        inputs.git.changed_paths(implementation, publication) == (AMENDMENT_PATH,),
        "receipt-only publication topology differs",
    )
    _require(
        AMENDMENT_PATH not in inputs.git.changed_paths(HISTORICAL_SOURCE, implementation),
        "reviewed implementation must precede the amendment record",
    )
    inputs.git.require_ancestor(PUBLISHED_EVIDENCE, implementation)
    inputs.git.require_ancestor(publication, current)
    _require(
        inputs.git.read_commit_artifact(publication, AMENDMENT_PATH) == document_raw,
        "published amendment bytes differ",
    )
    reviewed = _snapshot(inputs.git, implementation, current_rows)
    old_by_path = {row["path"]: row for row in historical_rows + public_rows}
    _require(
        all(old_by_path.get(path) is None for path in NEW_FILES),
        "new helper paths already appear in historical inventory",
    )
    changes = []
    for row in current_rows:
        old = old_by_path.get(row["path"])
        if old is None:
            _require(row["path"] in NEW_FILES, "unreviewed new tooling path")
        elif old != row:
            _require(
                row["path"] in MODIFIABLE_HISTORICAL_FILES,
                "protected historical tooling or signed input changed",
            )
        else:
            continue
        changes.append({"path": row["path"], "predecessor": old, "current": row})
    _require(
        type(expected["current_tooling_overlay"]) is list
        and len(expected["current_tooling_overlay"])
        <= len(MODIFIABLE_HISTORICAL_FILES) + len(NEW_FILES),
        "bounded exact overlay required",
    )
    for change in expected["current_tooling_overlay"]:
        _require(
            type(change) is dict and set(change) == {"path", "predecessor", "current"},
            "closed overlay row required",
        )
        _rows([change["current"]])
        if change["predecessor"] is not None:
            _rows([change["predecessor"]])
    _require(
        successor_core.canonical_bytes(expected["current_tooling_overlay"])
        == successor_core.canonical_bytes(changes),
        "overlay omits, reorders or invents a changed source binding",
    )
    _require(set(reviewed) == set(current_source_paths()), "reviewed dependency closure differs")
    _snapshot(inputs.git, current, current_rows)
    checked_now()
    # Recheck bound working bytes after the explicit callbacks. These bounded
    # observations do not claim a transaction across the entire filesystem.
    _current(root, current_rows)
    _require(
        architecture.read_bytes(root, AMENDMENT_PATH) == document_raw,
        "amendment changed during verification",
    )
    return PostclosureVerification(
        root.absolute(),
        current,
        architecture.raw_digest(CLAIM_DOMAIN + inputs.expected_claim),
        architecture.domain_digest("agent-assure:postclosure-current-inventory/v1", current_rows),
    )
