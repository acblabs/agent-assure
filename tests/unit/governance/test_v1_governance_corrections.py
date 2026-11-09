"""Draft retention and correction preparation cannot manufacture acceptance."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_architecture_governance as architecture  # noqa: E402
from scripts import v1_governance_corrections as corrections  # noqa: E402


def test_current_source_binding_preserves_original_package() -> None:
    original = (ROOT / corrections.DIRECTORY / "architecture-package.json").read_bytes()
    bindings = corrections.build_source_bindings(ROOT)
    assert bindings["predecessor_package_digest"] == corrections.PREDECESSOR_PACKAGE_DIGEST
    assert bindings["authorization_effect"] == "none"
    assert original == (ROOT / corrections.DIRECTORY / "architecture-package.json").read_bytes()


def test_source_check_rejects_unbound_tool_change(monkeypatch: pytest.MonkeyPatch) -> None:
    build = architecture.build_package

    def altered(root: Path) -> dict[str, Any]:
        package = build(root)
        binding = next(
            row for row in package["tooling_artifacts"] if row["path"] not in corrections.REPLACED
        )
        binding["sha256"] = "sha256:" + "f" * 64
        return package

    monkeypatch.setattr(architecture, "build_package", altered)
    with pytest.raises(architecture.ArchitectureError, match="unapproved"):
        corrections.build_source_bindings(ROOT)


def test_source_check_rejects_changed_accepted_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    build = architecture.build_package

    def altered(root: Path) -> dict[str, Any]:
        package = build(root)
        package["decisions"][0]["artifact"]["sha256"] = "sha256:" + "f" * 64
        return package

    monkeypatch.setattr(architecture, "build_package", altered)
    with pytest.raises(architecture.ArchitectureError, match="immutable"):
        corrections.build_source_bindings(ROOT)


def test_metadata_proposals_are_complete_but_not_human_decisions() -> None:
    prior = {
        "authoring_ledger": {
            "rows": [
                {"ticket_id": "V1-TEST-01", "dependency_anchor": {"ticket_ids": ["V1-BASE-01"]}}
            ]
        },
        "human_estimates": [
            {
                "ticket_id": "V1-TEST-01",
                "estimate_scope": "ticket_completion",
                "execution_estimates": [{"rationale": "Old human decision"}],
            }
        ],
    }
    before = copy.deepcopy(prior)
    proposed = corrections.propose_rows(prior, "2026-11-09T12:00:00Z")
    assert prior == before
    row = proposed[0]
    assert row["confidence"] == "low"
    assert row["current_status"] == "not_started"
    assert row["trusted_issue_time"] == "2026-11-09T12:00:00Z"
    assert "V1-BASE-01" in row["dependency_assumptions"][0]
    assert row["risk_assumptions"]
    assert row["execution_estimates"][0]["rationale"].startswith("Machine proposal:")


@pytest.mark.parametrize(
    "name",
    ["../escape", "/absolute", "NUL.json", "A:stream", "x\\y", "x. ", "snapshot-manifest.json"],
)
def test_bad_snapshot_names_fail_before_allocation(tmp_path: Path, name: str) -> None:
    output = tmp_path / ".governance-archive" / "review"
    with pytest.raises(architecture.ArchitectureError):
        corrections.publish_snapshot(tmp_path, output, {name: b"bytes"})
    assert not output.exists()


@pytest.mark.parametrize(
    "files",
    [
        {"A.json": b"x", "a.json": b"y"},
        {"x": b"x" * (4_194_304 + 1)},
        {str(i): b"x" for i in range(257)},
    ],
)
def test_snapshot_collision_and_limits_precede_allocation(
    tmp_path: Path, files: dict[str, bytes]
) -> None:
    output = tmp_path / ".governance-archive" / "review"
    with pytest.raises(architecture.ArchitectureError):
        corrections.publish_snapshot(tmp_path, output, files)
    assert not output.exists()


def test_snapshot_is_read_back_manifest_last_and_no_clobber(tmp_path: Path) -> None:
    output = tmp_path / ".governance-archive" / "review"
    files = {
        "subjects/example.json": b'{"value":1}\n',
        "claims/example.claim": b"domain\x00payload",
    }
    corrections.publish_snapshot(tmp_path, output, files)
    manifest = json.loads((output / "snapshot-manifest.json").read_text())
    assert manifest["authorization_effect"] == "none"
    assert len(manifest["files"]) == 2
    for row in manifest["files"]:
        assert architecture.raw_digest((output / row["path"]).read_bytes()) == row["sha256"]
    with pytest.raises(architecture.ArchitectureError, match="already exists"):
        corrections.publish_snapshot(tmp_path, output, {"changed": b"new"})
    assert not (output / "changed").exists()


def test_null_support_template_does_not_create_signing_outputs(tmp_path: Path) -> None:
    # Ownership is deliberately a human input; a no-op source check is not acceptance.
    assert corrections.main(["prepare", "--root", str(tmp_path)]) == 2
    assert not (tmp_path / ".governance-archive").exists()


def test_source_binding_refresh_is_atomic_and_draft_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / corrections.SOURCE_BINDINGS
    target.parent.mkdir(parents=True)
    target.write_text("{}\n")
    proposed = {
        "format": "agent-assure-sprint12-correction-source-bindings/1",
        "status": "prepared_for_human_review",
        "authorization_effect": "none",
    }
    monkeypatch.setattr(corrections, "build_source_bindings", lambda root: proposed)
    corrections.refresh_source_bindings(tmp_path)
    assert json.loads(target.read_bytes()) == proposed
    assert not target.with_suffix(".json.new").exists()
    accepted = {**proposed, "status": "accepted"}
    target.write_text(json.dumps(accepted))
    with pytest.raises(architecture.ArchitectureError, match="non-draft"):
        corrections.refresh_source_bindings(tmp_path)
    assert json.loads(target.read_bytes()) == accepted


def test_source_binding_refresh_preserves_unreviewed_staging_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / corrections.SOURCE_BINDINGS
    target.parent.mkdir(parents=True)
    target.write_text("{}\n")
    staging = target.with_suffix(".json.new")
    staging.write_bytes(b"Retained interrupted staging evidence")
    monkeypatch.setattr(corrections, "build_source_bindings", lambda root: {})
    with pytest.raises(FileExistsError):
        corrections.refresh_source_bindings(tmp_path)
    assert target.read_text() == "{}\n"
    assert staging.read_bytes() == b"Retained interrupted staging evidence"


def _support() -> dict[str, Any]:
    return {
        "person_id": "synthetic-owner",
        "organization_id": "synthetic-org",
        "capacity": "synthetic continuous primary coverage",
        "primary_role_ref": "synthetic-org/primary",
        "fallback_role_ref": "synthetic-org/fallback",
        "private_roster_ref": "synthetic-org/incident-response/on-call-roster",
        "private_roster_revision": "revision-7",
        "fallback_route_ref": "synthetic-org/private-route/fallback",
        "conflicts": "Synthetic maintainer self-review; no independent qualification",
        "limitations": "Synthetic test data; no real operational assignment",
        "primary_coverage_24x7": True,
        "fallback_coverage_24x7": True,
        "independent_fallback_person_and_route": True,
        "private_roster_revision_retained_and_auditable": True,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("fallback_role_ref", "synthetic-org/primary"),
        ("fallback_role_ref", "synthetic-org"),
        ("fallback_role_ref", "none"),
        ("private_roster_ref", "synthetic-org/roster/latest"),
        ("private_roster_revision", "current"),
        ("private_roster_revision", "pending/"),
        ("private_roster_revision", "latest#"),
        ("private_roster_revision", None),
        ("private_roster_revision_retained_and_auditable", False),
        ("primary_coverage_24x7", 1),
        ("fallback_coverage_24x7", False),
        ("independent_fallback_person_and_route", None),
        ("capacity", " "),
    ],
)
def test_support_coverage_cannot_be_implied(field: str, value: Any) -> None:
    adopted = _support()
    adopted[field] = value
    with pytest.raises(architecture.ArchitectureError):
        corrections.validate_support_adoption(adopted)


def _review() -> tuple[dict[str, Any], dict[str, bytes]]:
    """Independent tiny subject set; no production forecast or human signatures."""
    encode = lambda value: (json.dumps(value, indent=2) + "\n").encode()  # noqa: E731
    policy_path = f"{corrections.DIRECTORY}/support-policy-v2.json"
    security_bytes = b"Synthetic public security objectives\n"
    ownership_bytes = b"/scripts/** @synthetic-owner\n"
    policy = {
        "organization_id": "synthetic-org",
        "supported_line": "0.7.x",
        "response_targets": {"critical_acknowledgment_hours": 1},
        "security_intake_precedence": {
            "source_path": "SECURITY.md",
            "source_sha256": architecture.raw_digest(security_bytes),
        },
    }
    files = {
        "snapshot/" + policy_path: encode(policy),
        "snapshot/SECURITY.md": security_bytes,
        "snapshot/.github/CODEOWNERS": ownership_bytes,
    }
    claims = {}
    for name, spec in corrections.acceptance.CLAIM_SPECS.items():
        if name == "correction_close":
            subject_digest = corrections.acceptance.closure_subject_digest(claims)
        else:
            subject: Any = {"test_subject": name}
            if name == "foundation_adoption":
                subject = {
                    "codeowners_inspection": {
                        "path": ".github/CODEOWNERS",
                        "sha256": architecture.raw_digest(ownership_bytes),
                    }
                }
            if name == "support_policy":
                subject = {
                    **_support(),
                    "decision": "adopt_operational_support_policy",
                    "targets_become_operational_commitments": True,
                    "receipt_expiry_terminates_support": False,
                    "coverage_evidence": (
                        "policy_owner_attested_private_roster_not_independently_verified"
                    ),
                    "policy_path": policy_path,
                    "policy_sha256": architecture.raw_digest(encode(policy)),
                    "supported_line": policy["supported_line"],
                    "targets": policy["response_targets"],
                }
            path = "subjects/" + name + (".md" if name == "design_amendment" else ".json")
            files[path] = encode(subject)
            subject_digest = architecture.raw_digest(files[path])
        claims[name] = {
            "format": corrections.acceptance.CLAIM_FORMAT,
            "claim_id": name,
            "purpose": spec.purpose,
            "issuer_role": spec.role,
            "subject_digest": subject_digest,
            "predecessor_bundle_digest": "sha256:" + "a" * 64,
            "roadmap_digest": "sha256:" + "b" * 64,
            "correction_package_digest": "sha256:" + "c" * 64,
            "issued_at_utc": "2026-11-09T12:00:00Z",
            "valid_until_utc": "2026-11-10T12:00:00Z",
            "independence": "NO_INDEPENDENT_REVIEW",
            "authorization_effect": "development_governance_only",
        }
    package = {
        "format": "agent-assure-sprint12-correction-review/1",
        "status": "pending",
        "predecessor_bundle_digest": "sha256:" + "a" * 64,
        "roadmap_digest": "sha256:" + "b" * 64,
        "issued_at_utc": "2026-11-09T12:00:00Z",
        "valid_until_utc": "2026-11-10T12:00:00Z",
        "files": [
            {"path": path, "sha256": architecture.raw_digest(payload), "size_bytes": len(payload)}
            for path, payload in files.items()
        ],
    }
    digest = architecture.domain_digest("agent-assure:sprint12-correction-review/v1", package)
    for claim in claims.values():
        claim["correction_package_digest"] = digest
    claims["correction_close"]["subject_digest"] = corrections.acceptance.closure_subject_digest(
        {key: claim for key, claim in claims.items() if key != "correction_close"}
    )
    request = {
        **package,
        "package_digest": digest,
        "expected_claims": claims,
        "trusted_bootstrap_required": True,
        "sprint3_file_scope_authorized": False,
    }
    for name, claim in claims.items():
        files[f"claims/{name}.json"] = encode(claim)
        files[f"claims/{name}.claim"] = corrections.acceptance.claim_bytes(claim)
    files["review-request.json"] = encode(request)
    return request, files


def test_private_role_references_do_not_require_public_person_names() -> None:
    support = _support()
    assert "backup_person_id" not in support
    assert "fallback_person_name" not in support
    corrections.validate_support_adoption(support)


def test_organization_label_alone_does_not_establish_coverage() -> None:
    with pytest.raises(architecture.ArchitectureError, match="explicit support"):
        corrections.validate_support_adoption(
            {"person_id": "acblabs", "organization_id": "acblabs"}
        )


def test_support_target_comparison_does_not_alias_boolean_with_integer() -> None:
    request, files = _review()
    path = "subjects/support_policy.json"
    support = json.loads(files[path])
    support["targets"]["critical_acknowledgment_hours"] = True
    files[path] = corrections._json(support)
    for binding in request["files"]:
        if binding["path"] == path:
            binding.update(size_bytes=len(files[path]), sha256=architecture.raw_digest(files[path]))
    projection = {
        key: value
        for key, value in request.items()
        if key
        not in {
            "package_digest",
            "expected_claims",
            "trusted_bootstrap_required",
            "sprint3_file_scope_authorized",
        }
    }
    request["package_digest"] = architecture.domain_digest(
        "agent-assure:sprint12-correction-review/v1", projection
    )
    claims = request["expected_claims"]
    claims["support_policy"]["subject_digest"] = architecture.raw_digest(files[path])
    for claim in claims.values():
        claim["correction_package_digest"] = request["package_digest"]
    claims["correction_close"]["subject_digest"] = corrections.acceptance.closure_subject_digest(
        {key: claim for key, claim in claims.items() if key != "correction_close"}
    )
    for name, claim in claims.items():
        files[f"claims/{name}.json"] = corrections._json(claim)
        files[f"claims/{name}.claim"] = corrections.acceptance.claim_bytes(claim)
    files["review-request.json"] = corrections._json(request)
    with pytest.raises(architecture.ArchitectureError, match="targets or evidence strength"):
        corrections.verify_review_acceptance(
            request,
            files,
            {},
            {"release_policy_owner": SimpleNamespace(person_id="synthetic-owner")},
            None,
            now=None,
            prerequisite_valid_until_utc="2026-11-10T12:00:00Z",
        )


@pytest.mark.parametrize(
    "path,error",
    [
        ("snapshot/SECURITY.md", "public security"),
        ("snapshot/.github/CODEOWNERS", "ownership inspection"),
    ],
)
def test_rehashed_source_substitution_does_not_reuse_policy_or_inspection(
    path: str, error: str
) -> None:
    request, files = _review()
    files[path] += b"Substituted source\n"
    for binding in request["files"]:
        if binding["path"] == path:
            binding.update(size_bytes=len(files[path]), sha256=architecture.raw_digest(files[path]))
    projection = {
        key: value
        for key, value in request.items()
        if key
        not in {
            "package_digest",
            "expected_claims",
            "trusted_bootstrap_required",
            "sprint3_file_scope_authorized",
        }
    }
    request["package_digest"] = architecture.domain_digest(
        "agent-assure:sprint12-correction-review/v1", projection
    )
    claims = request["expected_claims"]
    for claim in claims.values():
        claim["correction_package_digest"] = request["package_digest"]
    claims["correction_close"]["subject_digest"] = corrections.acceptance.closure_subject_digest(
        {key: claim for key, claim in claims.items() if key != "correction_close"}
    )
    for name, claim in claims.items():
        files[f"claims/{name}.json"] = corrections._json(claim)
        files[f"claims/{name}.claim"] = corrections.acceptance.claim_bytes(claim)
    files["review-request.json"] = corrections._json(request)
    with pytest.raises(architecture.ArchitectureError, match=error):
        corrections.verify_review_acceptance(
            request,
            files,
            {},
            {"release_policy_owner": SimpleNamespace(person_id="synthetic-owner")},
            None,
            now=None,
            prerequisite_valid_until_utc="2026-11-10T12:00:00Z",
        )


def test_high_level_acceptance_checks_every_subject_before_signature_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, files = _review()
    sentinel = object()
    monkeypatch.setattr(
        corrections.acceptance, "verify_correction_acceptance", lambda *args, **kwargs: sentinel
    )
    assert (
        corrections.verify_review_acceptance(
            request,
            files,
            {},
            {"release_policy_owner": SimpleNamespace(person_id="synthetic-owner")},
            None,
            now=None,
            prerequisite_valid_until_utc="2026-11-10T12:00:00Z",
        )
        is sentinel
    )


@pytest.mark.parametrize(
    "mutation", ["wrong_owner", "extra_file", "changed_inventory_and_rehash", "changed_subject"]
)
def test_high_level_rejects_rebound_packages_and_owners(mutation: str) -> None:
    request, files = _review()
    owner = "synthetic-owner"
    if mutation == "wrong_owner":
        owner = "different-policy-owner"
    elif mutation == "extra_file":
        files["unlisted.py"] = b"must never be executed"
    elif mutation == "changed_inventory_and_rehash":
        request["source_bindings_digest"] = "sha256:" + "d" * 64
        projection = {
            key: value
            for key, value in request.items()
            if key
            not in {
                "package_digest",
                "expected_claims",
                "trusted_bootstrap_required",
                "sprint3_file_scope_authorized",
            }
        }
        request["package_digest"] = architecture.domain_digest(
            "agent-assure:sprint12-correction-review/v1", projection
        )
    else:
        files["subjects/support_policy.json"] = b'{"person_id":"changed"}'
    with pytest.raises(architecture.ArchitectureError):
        corrections.verify_review_acceptance(
            request,
            files,
            {},
            {"release_policy_owner": SimpleNamespace(person_id=owner)},
            None,
            now=None,
            prerequisite_valid_until_utc="2026-11-10T12:00:00Z",
        )
