from __future__ import annotations

import json
import os
import subprocess
from datetime import date, timedelta
from pathlib import Path

import pytest
import typer

from agent_assure.authoring.yaml_nodes import MAX_YAML_DEPTH
from agent_assure.cli.waivers import load_waivers, waiver_evaluation_date
from agent_assure.io_limits import MAX_JSON_DEPTH
from agent_assure.policies.base import (
    ControlResult,
    Waiver,
    apply_waivers,
    apply_waivers_with_dispositions,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.evaluation import (
    MAX_WAIVER_DISPOSITIONS,
    EvaluationSummary,
    EvaluationWaiverContext,
    WaiverDisposition,
    WaiverDispositionStatus,
)


def _waiver_payload() -> dict[str, str]:
    return {
        "waiver_id": "waiver-001",
        "owner": "waiver-owner-001",
        "rationale": "Temporary reviewed exception",
        "reason_code": "POLICY_FAILED",
        "finding_id": "finding-001",
        "artifact_digest": "a" * 64,
        "expires_on": "2030-01-01",
        "reviewer": "waiver-reviewer-001",
    }


def _current_evaluation_summary_payload(replay_context: dict[str, object]) -> dict[str, object]:
    return {
        "artifact_kind": "evaluation-summary",
        "schema_version": "0.6.6",
        "runset_id": "runset-001",
        "runset_digest": "c" * 64,
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "state": "pass",
        "replay_context": replay_context,
    }


@pytest.mark.parametrize(
    "unsafe_id",
    (
        "waiver\nforged",
        "waiver\u202eforged",
        "waiver with spaces",
        "w\u0430iver-confusable",
        "-waiver-leading-punctuation",
    ),
)
def test_waiver_ids_are_safe_ascii_machine_identifiers(unsafe_id: str) -> None:
    waiver_payload = _waiver_payload() | {"waiver_id": unsafe_id}
    with pytest.raises(ValueError, match="waiver_id"):
        Waiver.model_validate(waiver_payload)
    with pytest.raises(ValueError, match="waiver_id"):
        EvaluationWaiverContext.model_validate(waiver_payload)

    disposition_payload = {
        key: value for key, value in waiver_payload.items() if key != "artifact_digest"
    }
    disposition_payload["status"] = "unmatched_finding"
    with pytest.raises(ValueError, match="waiver_id"):
        WaiverDisposition.model_validate(disposition_payload)


def test_load_waivers_accepts_json_and_yaml_list_roots(tmp_path: Path) -> None:
    json_path = tmp_path / "waivers.json"
    yaml_path = tmp_path / "waivers.yaml"
    json_path.write_text(json.dumps([_waiver_payload()]), encoding="utf-8")
    yaml_path.write_text(
        "- " + json.dumps(_waiver_payload()) + "\n",
        encoding="utf-8",
    )

    assert load_waivers((json_path,))[0].waiver_id == "waiver-001"
    assert load_waivers((yaml_path,))[0].waiver_id == "waiver-001"


@pytest.mark.parametrize("suffix", [".json", ".yaml"])
def test_load_waivers_rejects_linked_ancestor(
    tmp_path: Path,
    suffix: str,
) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    path = real_directory / f"waivers{suffix}"
    path.write_text(json.dumps([_waiver_payload()]), encoding="utf-8")
    linked_directory = tmp_path / "linked"
    _create_directory_link(linked_directory, real_directory)

    with pytest.raises((OSError, ValueError), match="directory|link|reparse"):
        load_waivers((linked_directory / path.name,))


def test_load_waivers_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "waiver.json"
    path.write_text('{"waiver_id":"first","waiver_id":"second"}', encoding="utf-8")

    with pytest.raises(ValueError, match="contains duplicate object keys"):
        load_waivers((path,))


def test_load_waivers_rejects_excessive_json_nesting(tmp_path: Path) -> None:
    path = tmp_path / "waiver.json"
    path.write_text("[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1))

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
        load_waivers((path,))


def test_load_waivers_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = tmp_path / "waiver.yaml"
    path.write_text("waiver_id: first\nwaiver_id: second\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate YAML mapping key"):
        load_waivers((path,))


def test_load_waivers_rejects_yaml_aliases(tmp_path: Path) -> None:
    path = tmp_path / "waiver.yaml"
    path.write_text("- &waiver {waiver_id: first}\n- *waiver\n", encoding="utf-8")

    with pytest.raises(ValueError, match="aliases are not supported"):
        load_waivers((path,))


def test_load_waivers_rejects_excessive_yaml_nesting(tmp_path: Path) -> None:
    path = tmp_path / "waiver.yaml"
    path.write_text("[" * (MAX_YAML_DEPTH + 1) + "null" + "]" * (MAX_YAML_DEPTH + 1))

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
        load_waivers((path,))


def test_load_waivers_normalizes_unsupported_yaml_tag_error(tmp_path: Path) -> None:
    path = tmp_path / "waiver.yaml"
    path.write_text("waiver_id: !custom first\n", encoding="utf-8")

    with pytest.raises(ValueError, match="waiver YAML is invalid YAML"):
        load_waivers((path,))


def test_waiver_application_rejects_more_dispositions_than_the_report_bound() -> None:
    waiver = Waiver.model_validate(_waiver_payload())

    with pytest.raises(ValueError, match="waiver count exceeds disposition limit"):
        apply_waivers(
            (),
            waivers=(waiver,) * (MAX_WAIVER_DISPOSITIONS + 1),
            artifact_digest="a" * 64,
            today=date(2026, 7, 3),
        )


def test_waiver_application_requires_independent_reviewer_identity() -> None:
    today = date(2026, 7, 3)
    payload = _waiver_payload() | {
        "owner": "security-reviewer",
        "reviewer": "SECURITY-REVIEWER",
        "expires_on": (today + timedelta(days=1)).isoformat(),
    }

    with pytest.raises(ValueError, match="owner and reviewer must be different"):
        apply_waivers(
            (),
            waivers=(Waiver.model_validate(payload),),
            artifact_digest="a" * 64,
            today=today,
        )


def test_waiver_application_rejects_invisible_identity_characters() -> None:
    today = date(2026, 7, 3)
    payload = _waiver_payload() | {
        "owner": "security\u200d-reviewer",
        "reviewer": "security-reviewer",
        "expires_on": (today + timedelta(days=1)).isoformat(),
    }

    with pytest.raises(ValueError, match="must not contain control, formatting"):
        apply_waivers(
            (),
            waivers=(Waiver.model_validate(payload),),
            artifact_digest="a" * 64,
            today=today,
        )


def test_waiver_application_rejects_duplicate_ids_and_authority_bindings() -> None:
    today = date(2026, 7, 3)
    first = Waiver.model_validate(
        _waiver_payload() | {"expires_on": (today + timedelta(days=1)).isoformat()}
    )
    duplicate_id = first.model_copy(update={"finding_id": "finding-002"})
    duplicate_binding = first.model_copy(update={"waiver_id": "waiver-002"})

    with pytest.raises(ValueError, match="duplicate waiver_id"):
        apply_waivers(
            (),
            waivers=(first, duplicate_id),
            artifact_digest="a" * 64,
            today=today,
        )
    with pytest.raises(ValueError, match="duplicate waiver authority binding"):
        apply_waivers(
            (),
            waivers=(first, duplicate_binding),
            artifact_digest="a" * 64,
            today=today,
        )


def test_waiver_cannot_rewrite_not_evaluated_as_warning() -> None:
    today = date(2026, 7, 3)
    result = ControlResult(
        control_id="tool_allowlist",
        case_id="case-not-evaluated",
        state=GateState.not_evaluated,
        reason_code=ReasonCode.NOT_EVALUATED,
        severity=Severity.warning,
        target="tool-policy",
        message="tool policy could not be evaluated",
    )
    waiver = Waiver.model_validate(
        _waiver_payload()
        | {
            "reason_code": result.reason_code.value,
            "finding_id": result.finding_id,
            "expires_on": (today + timedelta(days=1)).isoformat(),
        }
    )

    application = apply_waivers_with_dispositions(
        (result,),
        waivers=(waiver,),
        artifact_digest="a" * 64,
        today=today,
    )

    assert application.results == (result,)
    assert application.results[0].state is GateState.not_evaluated
    assert application.results[0].waived is False
    assert application.dispositions[0].status is WaiverDispositionStatus.unmatched_finding


def test_versionless_waiver_outputs_defer_governance_to_versioned_parents() -> None:
    shared = {
        "waiver_id": "waiver-001",
        "owner": "\uff33ecurity-Reviewer",
        "reviewer": "security-reviewer",
        "rationale": "Temporary reviewed exception",
        "reason_code": "POLICY_FAILED",
        "finding_id": "finding-001",
        "expires_on": "2026-07-04",
    }

    assert WaiverDisposition.model_validate(shared | {"status": "matched"}).owner == shared["owner"]
    assert (
        EvaluationWaiverContext.model_validate(shared | {"artifact_digest": "a" * 64}).owner
        == shared["owner"]
    )


def test_evaluation_replay_context_caps_persisted_waiver_expiry() -> None:
    evaluation_date = date(2026, 7, 3)
    waiver = {
        "waiver_id": "waiver-001",
        "owner": "waiver-owner-001",
        "reviewer": "waiver-reviewer-001",
        "rationale": "Temporary reviewed exception",
        "reason_code": "POLICY_FAILED",
        "finding_id": "finding-001",
        "artifact_digest": "a" * 64,
        "expires_on": (evaluation_date + timedelta(days=91)).isoformat(),
    }
    context = {
        "suite_digest": "b" * 64,
        "gate_profile": {
            "profile_id": "default",
            "fail_severities": ["error"],
            "fail_reason_codes": [],
            "fail_on_warn": False,
            "fail_on_not_evaluated": False,
        },
        "waivers": [waiver],
        "evaluation_date": evaluation_date,
    }

    with pytest.raises(ValueError, match="no more than 90 days"):
        EvaluationSummary.model_validate(_current_evaluation_summary_payload(context))

    waiver["expires_on"] = (evaluation_date + timedelta(days=90)).isoformat()
    summary = EvaluationSummary.model_validate(_current_evaluation_summary_payload(context))
    assert summary.replay_context is not None
    assert summary.replay_context.waivers[0].expires_on == date(2026, 10, 1)


def test_evaluation_replay_context_expiry_horizon_is_date_max_safe() -> None:
    evaluation_date = date.max - timedelta(days=1)
    context = {
        "suite_digest": "b" * 64,
        "gate_profile": {
            "profile_id": "default",
            "fail_severities": ["error"],
            "fail_reason_codes": [],
            "fail_on_warn": False,
            "fail_on_not_evaluated": False,
        },
        "waivers": [
            {
                "waiver_id": "waiver-001",
                "owner": "waiver-owner-001",
                "reviewer": "waiver-reviewer-001",
                "rationale": "Temporary reviewed exception",
                "reason_code": "POLICY_FAILED",
                "finding_id": "finding-001",
                "artifact_digest": "a" * 64,
                "expires_on": date.max,
            }
        ],
        "evaluation_date": evaluation_date,
    }

    summary = EvaluationSummary.model_validate(_current_evaluation_summary_payload(context))
    assert summary.replay_context is not None
    assert summary.replay_context.waivers[0].expires_on == date.max


def test_waiver_application_caps_expiry_at_ninety_days() -> None:
    today = date(2026, 7, 3)
    payload = _waiver_payload() | {
        "expires_on": (today + timedelta(days=91)).isoformat(),
    }

    with pytest.raises(ValueError, match="no more than 90 days"):
        apply_waivers(
            (),
            waivers=(Waiver.model_validate(payload),),
            artifact_digest="a" * 64,
            today=today,
        )


def test_waiver_governance_text_must_be_safe_to_persist() -> None:
    payload = _waiver_payload() | {"rationale": "password is CorrectHorseBatteryStaple"}

    with pytest.raises(ValueError, match="sensitive-looking content"):
        Waiver.model_validate(payload)


def test_waiver_bearing_cli_date_cannot_be_backdated() -> None:
    local_today = date.today()
    payload = _waiver_payload() | {
        "expires_on": (local_today + timedelta(days=1)).isoformat(),
    }
    waiver = Waiver.model_validate(payload)

    assert waiver_evaluation_date(local_today, waivers=(waiver,)) == local_today
    with pytest.raises(typer.BadParameter, match="current local or UTC date"):
        waiver_evaluation_date(local_today - timedelta(days=2), waivers=(waiver,))


def test_waiver_free_cli_date_remains_replayable() -> None:
    historical = date(2026, 7, 3)

    assert waiver_evaluation_date(historical, waivers=()) == historical


def _create_directory_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except OSError as exc:
        if os.name != "nt":
            pytest.skip(f"directory links unavailable: {exc}")
    completed = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(f"directory junctions unavailable: {completed.stderr}")
