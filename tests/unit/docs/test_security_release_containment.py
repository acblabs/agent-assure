from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.check_docs_alignment as docs_alignment  # noqa: E402

GOVERNANCE_PATHS = (
    Path("SECURITY.md"),
    Path("README.md"),
    Path("mkdocs.yml"),
    Path("docs/index.md"),
    Path("docs/release_pypi.md"),
    Path("docs/release_notes/v0.7.0.md"),
    Path("docs/security_release_containment.md"),
    Path("docs/templates/security_release_risk_acceptance.yaml"),
)


def _copy_governance_files(destination: Path) -> None:
    for relative_path in GOVERNANCE_PATHS:
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            (ROOT / relative_path).read_text(encoding="utf-8"),
            encoding="utf-8",
        )


def test_security_release_containment_governance_is_aligned() -> None:
    assert docs_alignment._check_security_release_containment() == []


def test_risk_acceptance_template_defaults_fail_closed() -> None:
    template = ROOT / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    payload = yaml.safe_load(template.read_text(encoding="utf-8"))

    assert payload["record_schema"] == docs_alignment.SECURITY_RISK_RECORD_SCHEMA
    assert payload["status"] == "draft"
    assert payload["authority_boundary"]["operational_risk_acceptance_only"] is True
    for action in docs_alignment.NON_AUTHORIZING_ACTIONS:
        assert payload["authority_boundary"][action] is False
    assert (
        payload["roles"]["independent_security_risk_approver"]["distinct_person_required"] is True
    )
    assert payload["approval"]["accountable_owner_decision"] == "pending"
    assert payload["approval"]["independent_approver_decision"] == "pending"
    assert payload["intake_policy"]["policy_id"] == docs_alignment.SECURITY_INTAKE_POLICY_ID
    assert (
        payload["intake_policy"]["policy_revision"]
        == docs_alignment.SECURITY_INTAKE_POLICY_REVISION
    )
    assert payload["intake_policy"]["clock_basis"] == docs_alignment.SECURITY_INTAKE_CLOCK_BASIS
    assert (
        payload["intake_policy"]["critical"]
        == docs_alignment.SECURITY_INTAKE_OBJECTIVES["critical"]
    )
    assert payload["intake_policy"]["high"] == docs_alignment.SECURITY_INTAKE_OBJECTIVES["high"]
    assert payload["intake_policy"]["severity_specific_objectives_override_general_targets"]
    assert payload["roles"]["critical_intake_primary_on_call"]["continuous_coverage_required"]
    assert payload["roles"]["critical_intake_independent_fallback_on_call"][
        "continuous_coverage_required"
    ]
    assert payload["roles"]["critical_intake_independent_fallback_on_call"][
        "distinct_person_from_primary_required"
    ]
    assert payload["timing"]["expires_at_utc"] == ""
    assert "record_snapshot_sha256" not in payload["audit"]
    assert "record_snapshot_external_digest_event_reference" not in payload["audit"]
    assert payload["audit"]["record_snapshot_digest_algorithm"] == "sha256"
    assert payload["audit"]["record_snapshot_digest_stored_outside_record"] is True


def test_alignment_rejects_publication_authority_in_template(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "  pypi_publication: false",
            "  pypi_publication: true",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert (
        "security risk-acceptance template must deny publication authority: pypi_publication"
    ) in failures


def test_alignment_rejects_non_distinct_security_approver(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "    distinct_person_required: true",
            "    distinct_person_required: false",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert "security risk-acceptance template must require a distinct approver" in failures


def test_alignment_rejects_missing_expiry_field(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            '  expires_at_utc: ""\n',
            "",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert "security risk-acceptance template missing field: timing.expires_at_utc" in failures


def test_alignment_rejects_recursive_record_snapshot_digest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            '  record_snapshot_export_reference: ""\n',
            '  record_snapshot_export_reference: ""\n  record_snapshot_sha256: "0"\n',
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert (
        "security risk-acceptance template must not contain a recursive record snapshot digest"
    ) in failures


def test_alignment_rejects_forward_record_snapshot_digest_event_reference(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "  record_snapshot_digest_stored_outside_record: true\n",
            "  record_snapshot_external_digest_event_reference: pending\n"
            "  record_snapshot_digest_stored_outside_record: true\n",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert (
        "security risk-acceptance template must not contain a forward record "
        "snapshot digest-event reference"
    ) in failures


def test_alignment_rejects_missing_intake_clock_timestamp(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            '  clock_started_at_utc: ""\n',
            "",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert (
        "security risk-acceptance template missing field: incident_intake.clock_started_at_utc"
    ) in failures


def test_alignment_rejects_weakened_critical_intake_objective(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "    acknowledgement_minutes: 60\n",
            "    acknowledgement_minutes: 600\n",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert (
        "security risk-acceptance template has unexpected intake objective: "
        "critical.acknowledgement_minutes"
    ) in failures


def test_alignment_rejects_noncontinuous_primary_intake_coverage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "    continuous_coverage_required: true\n",
            "    continuous_coverage_required: false\n",
            1,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert "security risk-acceptance template must require continuous primary coverage" in failures


def test_alignment_rejects_fallback_that_can_be_the_primary_person(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "    distinct_person_from_primary_required: true\n",
            "    distinct_person_from_primary_required: false\n",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert "security risk-acceptance template must require a distinct fallback person" in failures


def test_alignment_rejects_missing_severity_precedence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    security = tmp_path / "SECURITY.md"
    security.write_text(
        security.read_text(encoding="utf-8").replace(
            "The severity-specific objectives take precedence\n"
            "over the general three- and seven-business-day targets.",
            "The objectives are informational.",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert any(
        failure.startswith("public security policy missing intake control: ")
        and "severity-specific objectives take precedence" in failure
        for failure in failures
    )


def test_alignment_rejects_delayed_critical_fallback_page(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    document = tmp_path / "docs" / "security_release_containment.md"
    document.write_text(
        document.read_text(encoding="utf-8").replace(
            "within 15 elapsed minutes also pages",
            "within 150 elapsed minutes also pages",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert any(
        failure.startswith("security correction containment policy missing intake control: ")
        and "within 15 elapsed minutes" in failure
        for failure in failures
    )


def test_alignment_rejects_missing_escalation_audit_timestamp(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _copy_governance_files(tmp_path)
    template = tmp_path / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            '  fallback_activated_at_utc: ""\n',
            "",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_security_release_containment()

    assert (
        "security risk-acceptance template missing field: escalation.fallback_activated_at_utc"
        in failures
    )
