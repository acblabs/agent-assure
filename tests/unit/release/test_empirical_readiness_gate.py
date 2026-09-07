from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.check_empirical_readiness as readiness_gate
from agent_assure.study.readiness import EmpiricalReadinessAssessment
from tests.unit.schema.test_pilot_evidence import _external_evidence
from tests.unit.test_pilot_bundle import (
    EVIDENCE_NAME,
    RECEIPT_NAME,
    _wheel_bytes,
    _write_bundle,
)

ROOT = Path(__file__).resolve().parents[3]


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _stub_validated_evidence(
    monkeypatch: pytest.MonkeyPatch,
    *,
    checkpoint_ready: bool,
    blocking_reasons: tuple[str, ...],
) -> tuple[str, str]:
    study_digest = "a" * 64
    pilot_digest = "b" * 64
    benchmark_digest = "c" * 64
    report = SimpleNamespace(report_digest=study_digest)
    study_registration_receipt = SimpleNamespace(
        review_receipt_digest="f" * 64,
        reviewer_identity_authentication="out_of_band_not_machine_verified",
    )
    study_execution_receipt = SimpleNamespace(
        execution_review_receipt_digest="8" * 64,
        reviewer_identity_authentication="out_of_band_not_machine_verified",
    )
    study_method_review_receipt = SimpleNamespace(
        method_review_receipt_digest="7" * 64,
        attestation_basis="qualified_human_statistical_review",
        reviewer_identity_authentication="out_of_band_not_machine_verified",
    )
    study_bundle = SimpleNamespace(
        report=report,
        file_count=26,
        total_bytes=456,
        registration_record_sha256="9" * 64,
        registration_review_receipt=study_registration_receipt,
        statistical_method_review_receipt=study_method_review_receipt,
        statistical_method_review_verified=True,
        execution_review_receipt=study_execution_receipt,
        execution_review_verified=True,
    )
    pilot = SimpleNamespace(pilot_evidence_digest=pilot_digest)
    review_receipt = SimpleNamespace(review_receipt_digest="d" * 64)
    verified_pilot = SimpleNamespace(
        evidence=pilot,
        review_receipt=review_receipt,
        artifact_manifest_digest="e" * 64,
        total_bytes=123,
    )
    benchmark = SimpleNamespace(benchmark_digest=benchmark_digest)
    assessment = EmpiricalReadinessAssessment(
        study_bundle_verified=True,
        study_bundle_file_count=26,
        study_bundle_bytes_verified=456,
        study_registration_evidence_verified=True,
        study_statistical_method_review_verified=checkpoint_ready,
        study_execution_review_verified=checkpoint_ready,
        study_evidence_satisfied=checkpoint_ready,
        study_real_provider_origin_satisfied=checkpoint_ready,
        canonical_benchmark_satisfied=checkpoint_ready,
        external_pilot_bundle_verified=True,
        external_pilot_attempt_satisfied=True,
        external_pilot_publication_authorized=True,
        pilot_subject_implementation_satisfied=True,
        pilot_subject_version_satisfied=True,
        pilot_learning_captured=True,
        checkpoint_ready=checkpoint_ready,
        exact_candidate_gate_eligible=False,
        clean_reproduction_gate_eligible=False,
        ci_integration_gate_eligible=False,
        blocking_reasons=blocking_reasons,
    )
    monkeypatch.setattr(
        readiness_gate,
        "load_and_validate_study_bundle",
        lambda _path: study_bundle,
    )
    monkeypatch.setattr(
        readiness_gate,
        "load_verified_external_pilot_bundle",
        lambda _root, **_kwargs: verified_pilot,
    )
    monkeypatch.setattr(readiness_gate, "_load_canonical_benchmark", lambda: benchmark)
    monkeypatch.setattr(readiness_gate, "_load_benchmark", lambda _path: benchmark)
    monkeypatch.setattr(readiness_gate, "_bundle_root_is_absent", lambda _path: False)
    monkeypatch.setattr(
        readiness_gate,
        "assess_empirical_readiness",
        lambda _study_bundle, _pilot, _benchmark, _expected_release: assessment,
    )
    return study_digest, pilot_digest


def test_publish_gate_orders_empirical_readiness_before_release_work() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert (
        "release-publish-check: empirical-readiness\n"
        '\t$(MAKE) release-check EXPECTED_RELEASE="$(EXPECTED_RELEASE)"'
    ) in makefile
    assert '--benchmark "examples/process_equivalence_benchmark_v0_2/benchmark.json"' in makefile
    assert '--study-bundle-root "$(EMPIRICAL_STUDY_BUNDLE_ROOT)"' in makefile
    assert '--external-pilot-bundle-root "$(EXTERNAL_PILOT_BUNDLE_ROOT)"' in makefile
    assert '--external-pilot-review-receipt "$(EXTERNAL_PILOT_REVIEW_RECEIPT)"' in makefile
    assert '--expected-release "$(EXPECTED_RELEASE)"' in makefile


def test_publish_workflows_pin_the_closed_empirical_bundle_layouts() -> None:
    for workflow_name in ("publish-testpypi.yml", "release.yml"):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        assert "EMPIRICAL_STUDY_BUNDLE_ROOT: evidence/empirical/real-model-study" in workflow
        assert "EXTERNAL_PILOT_BUNDLE_ROOT: evidence/empirical/external-pilot" in workflow
        assert "EXTERNAL_PILOT_EVIDENCE: external-pilot-evidence.json" in workflow
        assert (
            "EXTERNAL_PILOT_REVIEW_RECEIPT: external-pilot-independence-review.json"
        ) in workflow


def test_committed_canonical_benchmark_matches_packaged_mirror_exactly() -> None:
    benchmark = readiness_gate._load_canonical_benchmark()

    assert (
        readiness_gate.CANONICAL_BENCHMARK_PATH.read_bytes()
        == readiness_gate.PACKAGED_BENCHMARK_PATH.read_bytes()
    )
    assert (
        benchmark.benchmark_digest
        == "9f734a3910933d92e5993e3e6f54ca23756146848d78e17317480f48ab54bb54"
    )


def test_canonical_benchmark_mirror_read_is_size_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(readiness_gate, "MAX_ARTIFACT_JSON_BYTES", 1)

    with pytest.raises(ValueError, match="exceeds maximum supported size"):
        readiness_gate._load_canonical_benchmark()


def test_operator_benchmark_override_cannot_replace_committed_trust_anchor(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canonical = SimpleNamespace(benchmark_digest="c" * 64)
    unrelated = SimpleNamespace(benchmark_digest="d" * 64)
    monkeypatch.setattr(readiness_gate, "_load_canonical_benchmark", lambda: canonical)
    monkeypatch.setattr(readiness_gate, "_load_benchmark", lambda _path: unrelated)

    exit_code = readiness_gate.main(
        [
            "--study-bundle-root",
            "study-bundle",
            "--external-pilot-bundle-root",
            "pilot-bundle",
            "--external-pilot-evidence",
            "pilot-evidence.json",
            "--external-pilot-review-receipt",
            "pilot-review.json",
            "--benchmark",
            "operator-selected.json",
            "--expected-release",
            "0.6.6",
        ]
    )

    assert exit_code == 1
    assert json.loads(capsys.readouterr().out) == {
        "blocking_reasons": ["empirical-evidence-invalid-or-unavailable"],
        "checkpoint_ready": False,
        "failure_category": "ValueError",
    }


def test_empirical_readiness_gate_accepts_only_valid_ready_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    study_digest, pilot_digest = _stub_validated_evidence(
        monkeypatch,
        checkpoint_ready=True,
        blocking_reasons=(),
    )

    exit_code = readiness_gate.main(
        [
            "--study-bundle-root",
            "study-bundle",
            "--external-pilot-bundle-root",
            "pilot-bundle",
            "--external-pilot-evidence",
            "pilot-evidence.json",
            "--external-pilot-review-receipt",
            "pilot-review.json",
            "--expected-release",
            "0.6.6rc1",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["checkpoint_ready"] is True
    assert result["blocking_reasons"] == []
    assert result["study_report_digest"] == study_digest
    assert result["study_bundle_files_verified"] == 26
    assert result["study_bundle_bytes_verified"] == 456
    assert result["study_registration_record_sha256"] == "9" * 64
    assert result["study_registration_review_receipt_digest"] == "f" * 64
    assert result["study_registration_review_state"] == "operator_attested"
    assert (
        result["study_registration_reviewer_identity_authentication"]
        == "out_of_band_not_machine_verified"
    )
    assert result["study_statistical_method_review_receipt_digest"] == "7" * 64
    assert result["study_statistical_method_review_state"] == "qualified_operator_attested"
    assert (
        result["study_statistical_method_review_attestation_basis"]
        == "qualified_human_statistical_review"
    )
    assert (
        result["study_statistical_method_reviewer_identity_authentication"]
        == "out_of_band_not_machine_verified"
    )
    assert result["study_execution_review_receipt_digest"] == "8" * 64
    assert result["study_execution_review_state"] == "operator_attested"
    assert (
        result["study_execution_reviewer_identity_authentication"]
        == "out_of_band_not_machine_verified"
    )
    assert result["external_pilot_evidence_digest"] == pilot_digest
    assert result["external_pilot_review_receipt_digest"] == "d" * 64
    assert result["external_pilot_artifact_manifest_digest"] == "e" * 64
    assert result["external_pilot_bundle_bytes_verified"] == 123
    assert result["external_pilot_independence_review_state"] == "operator_attested"
    assert (
        result["external_pilot_reviewer_identity_authentication"]
        == "out_of_band_not_machine_verified"
    )
    assert result["canonical_benchmark_digest"] == "c" * 64
    assert result["expected_release"] == "0.6.6rc1"


@pytest.mark.parametrize(
    ("raised", "expected_category"),
    (
        (FileNotFoundError("private missing-artifact detail"), "FileNotFoundError"),
        (TypeError("private internal-defect detail"), "TypeError"),
    ),
)
def test_empirical_readiness_gate_emits_only_value_free_failure_categories(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    raised: Exception,
    expected_category: str,
) -> None:
    def fail_check(*_args: object, **_kwargs: object) -> tuple[bool, dict[str, object]]:
        raise raised

    monkeypatch.setattr(readiness_gate, "check_empirical_readiness", fail_check)

    exit_code = readiness_gate.main(
        [
            "--study-bundle-root",
            "study-bundle",
            "--external-pilot-bundle-root",
            "pilot-bundle",
            "--external-pilot-evidence",
            "pilot-evidence.json",
            "--external-pilot-review-receipt",
            "pilot-review.json",
            "--expected-release",
            "0.6.6",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr().out
    assert str(raised) not in captured
    assert json.loads(captured) == {
        "blocking_reasons": ["empirical-evidence-invalid-or-unavailable"],
        "checkpoint_ready": False,
        "failure_category": expected_category,
    }


def test_empirical_readiness_gate_normalizes_corrupt_deflate_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    wheel = bytearray(_wheel_bytes(compression=zipfile.ZIP_DEFLATED))
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        metadata = archive.getinfo("agent_assure-0.6.6.dist-info/METADATA")
        name_length, extra_length = struct.unpack_from("<HH", wheel, metadata.header_offset + 26)
        compressed_offset = metadata.header_offset + 30 + name_length + extra_length
    wheel[compressed_offset] ^= 0xFF
    pilot_root = tmp_path / "pilot-bundle"
    _write_bundle(pilot_root, distribution_bytes=bytes(wheel))
    benchmark = SimpleNamespace(benchmark_digest="c" * 64)
    monkeypatch.setattr(readiness_gate, "_load_canonical_benchmark", lambda: benchmark)
    monkeypatch.setattr(readiness_gate, "_load_benchmark", lambda _path: benchmark)

    exit_code = readiness_gate.main(
        [
            "--study-bundle-root",
            str(tmp_path / "missing-study-bundle"),
            "--external-pilot-bundle-root",
            str(pilot_root),
            "--external-pilot-evidence",
            EVIDENCE_NAME,
            "--external-pilot-review-receipt",
            RECEIPT_NAME,
            "--expected-release",
            "0.6.6",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out
    assert "decompress" not in captured.out
    assert json.loads(captured.out) == {
        "blocking_reasons": ["empirical-evidence-invalid-or-unavailable"],
        "checkpoint_ready": False,
        "failure_category": "ValueError",
    }


def test_missing_bundle_roots_surface_assessor_blocking_reasons(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = readiness_gate.main(
        [
            "--study-bundle-root",
            str(tmp_path / "missing-study-bundle"),
            "--external-pilot-bundle-root",
            str(tmp_path / "missing-pilot-bundle"),
            "--external-pilot-evidence",
            "external-pilot-evidence.json",
            "--external-pilot-review-receipt",
            "external-pilot-independence-review.json",
            "--expected-release",
            "0.6.6",
        ]
    )

    assert exit_code == 1
    result = json.loads(capsys.readouterr().out)
    reasons = result["blocking_reasons"]
    assert "real-model-study-bundle-not-verified" in reasons
    assert "external-pilot-bundle-not-verified" in reasons
    assert "external-ci-pilot-not-attempted" in reasons
    assert "empirical-evidence-invalid-or-unavailable" not in reasons
    assert "failure_category" not in result
    assert result["study_report_digest"] is None
    assert result["study_bundle_files_verified"] == 0
    assert result["external_pilot_evidence_digest"] is None
    assert result["external_pilot_bundle_bytes_verified"] == 0


def test_empirical_readiness_gate_fails_closed_without_leaking_invalid_values(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "patient-secret-invalid-study"
    study_root = tmp_path / "study-bundle"
    study_root.mkdir()
    pilot_root = tmp_path / "pilot-bundle"
    pilot_root.mkdir()
    pilot_path = pilot_root / "pilot-evidence.json"
    _write_json(
        study_root / "real-model-study-report.json",
        {"artifact_kind": secret},
    )
    _write_json(pilot_path, {})

    exit_code = readiness_gate.main(
        [
            "--study-bundle-root",
            str(study_root),
            "--external-pilot-bundle-root",
            str(pilot_root),
            "--external-pilot-evidence",
            pilot_path.name,
            "--external-pilot-review-receipt",
            "pilot-review.json",
            "--expected-release",
            "0.6.6",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert secret not in captured.out
    result = json.loads(captured.out)
    assert result["blocking_reasons"] == ["empirical-evidence-invalid-or-unavailable"]
    assert result["checkpoint_ready"] is False
    assert isinstance(result["failure_category"], str)
    assert result["failure_category"].endswith("Error")


def test_empirical_readiness_gate_rejects_valid_but_ineligible_evidence(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _stub_validated_evidence(
        monkeypatch,
        checkpoint_ready=False,
        blocking_reasons=("real-model-study-not-satisfied",),
    )

    exit_code = readiness_gate.main(
        [
            "--study-bundle-root",
            "study-bundle",
            "--external-pilot-bundle-root",
            "pilot-bundle",
            "--external-pilot-evidence",
            "pilot-evidence.json",
            "--external-pilot-review-receipt",
            "pilot-review.json",
            "--expected-release",
            "0.6.6",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["checkpoint_ready"] is False
    assert result["blocking_reasons"] == ["real-model-study-not-satisfied"]
    assert "failure_category" not in result


def test_bare_external_evidence_with_fake_hashes_and_no_files_fails_checker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    benchmark = SimpleNamespace(benchmark_digest="c" * 64)
    study_bundle = SimpleNamespace(
        report=SimpleNamespace(report_digest="a" * 64),
        file_count=24,
        total_bytes=456,
    )
    monkeypatch.setattr(readiness_gate, "_load_canonical_benchmark", lambda: benchmark)
    monkeypatch.setattr(readiness_gate, "_load_benchmark", lambda _path: benchmark)
    monkeypatch.setattr(
        readiness_gate,
        "load_and_validate_study_bundle",
        lambda _path: study_bundle,
    )
    bundle_root = tmp_path / "pilot-bundle"
    bundle_root.mkdir()
    _write_json(
        bundle_root / "external-pilot-evidence.json",
        _external_evidence().model_dump(mode="json"),
    )

    exit_code = readiness_gate.main(
        [
            "--study-bundle-root",
            "study-bundle",
            "--external-pilot-bundle-root",
            str(bundle_root),
            "--external-pilot-evidence",
            "external-pilot-evidence.json",
            "--external-pilot-review-receipt",
            "external-pilot-independence-review.json",
            "--expected-release",
            "0.6.6",
        ]
    )

    assert exit_code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["blocking_reasons"] == ["empirical-evidence-invalid-or-unavailable"]
    assert result["checkpoint_ready"] is False
    assert isinstance(result["failure_category"], str)
    assert result["failure_category"].endswith("Error")
