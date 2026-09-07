from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.io_limits import (  # noqa: E402
    MAX_ARTIFACT_JSON_BYTES,
    load_json_bytes_bounded,
    read_bytes_bounded_from_filesystem_root,
)
from agent_assure.pilot_bundle import (  # noqa: E402
    VerifiedExternalPilotBundle,
    load_verified_external_pilot_bundle,
)
from agent_assure.schema.benchmark import (  # noqa: E402
    ProcessEquivalenceBenchmarkManifest,
)
from agent_assure.schema.validation import (  # noqa: E402
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)
from agent_assure.study.readiness import assess_empirical_readiness  # noqa: E402
from agent_assure.study_bundle import (  # noqa: E402
    ValidatedStudyBundle,
    load_and_validate_study_bundle,
)

CANONICAL_BENCHMARK_PATH = (
    ROOT / "examples" / "process_equivalence_benchmark_v0_2" / "benchmark.json"
)
PACKAGED_BENCHMARK_PATH = (
    ROOT
    / "src"
    / "agent_assure"
    / "examples"
    / "process_equivalence_benchmark_v0_2"
    / "benchmark.json"
)


def _load_benchmark(path: Path) -> ProcessEquivalenceBenchmarkManifest:
    payload = load_validated_artifact_payload(path, "process-equivalence-benchmark")
    return project_validated_artifact_payload(
        payload,
        ProcessEquivalenceBenchmarkManifest,
        kind="process-equivalence-benchmark",
    )


def _load_benchmark_bytes(
    data: bytes,
    *,
    label: str,
) -> ProcessEquivalenceBenchmarkManifest:
    payload = load_json_bytes_bounded(
        data,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=label,
    )
    validate_loaded_artifact_payload(payload, "process-equivalence-benchmark")
    return project_validated_artifact_payload(
        payload,
        ProcessEquivalenceBenchmarkManifest,
        kind="process-equivalence-benchmark",
    )


def _load_canonical_benchmark() -> ProcessEquivalenceBenchmarkManifest:
    """Load the committed trust anchor and require its packaged mirror byte-for-byte."""

    canonical_bytes = read_bytes_bounded_from_filesystem_root(
        CANONICAL_BENCHMARK_PATH,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="canonical process-equivalence benchmark",
    )
    packaged_bytes = read_bytes_bounded_from_filesystem_root(
        PACKAGED_BENCHMARK_PATH,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="packaged process-equivalence benchmark mirror",
    )
    if canonical_bytes != packaged_bytes:
        raise ValueError("canonical benchmark and packaged mirror differ")
    canonical = _load_benchmark_bytes(
        canonical_bytes,
        label="canonical process-equivalence benchmark",
    )
    packaged = _load_benchmark_bytes(
        packaged_bytes,
        label="packaged process-equivalence benchmark mirror",
    )
    if canonical != packaged:
        raise ValueError("canonical benchmark and packaged mirror do not validate identically")
    return canonical


def _bundle_root_is_absent(path: Path) -> bool:
    """Return true only when the requested bundle root does not exist.

    Existing files, broken links, inaccessible paths, and malformed directories
    must continue into the bounded verifier and fail with a value-free failure
    category. Only an actually absent root represents evidence that has not yet
    been produced and can therefore be projected by the readiness assessor.
    """

    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def _load_study_bundle_if_present(path: Path) -> ValidatedStudyBundle | None:
    if _bundle_root_is_absent(path):
        return None
    return load_and_validate_study_bundle(path)


def _load_external_pilot_if_present(
    bundle_root: Path,
    *,
    evidence_path: Path,
    review_receipt_path: Path,
    expected_release: str,
) -> VerifiedExternalPilotBundle | None:
    if _bundle_root_is_absent(bundle_root):
        return None
    return load_verified_external_pilot_bundle(
        bundle_root,
        evidence_path=evidence_path,
        review_receipt_path=review_receipt_path,
        expected_release=expected_release,
    )


def check_empirical_readiness(
    study_bundle_root: Path,
    external_pilot_bundle_root: Path,
    external_pilot_evidence_path: Path,
    external_pilot_review_receipt_path: Path,
    benchmark_path: Path = CANONICAL_BENCHMARK_PATH,
    *,
    expected_release: str,
) -> tuple[bool, dict[str, object]]:
    """Validate exact artifacts and derive the v0.6.6 empirical checkpoint."""

    canonical_benchmark = _load_canonical_benchmark()
    supplied_benchmark = _load_benchmark(benchmark_path)
    if supplied_benchmark != canonical_benchmark:
        raise ValueError("supplied benchmark is not the committed canonical benchmark")
    study_bundle = _load_study_bundle_if_present(study_bundle_root)
    verified_pilot = _load_external_pilot_if_present(
        external_pilot_bundle_root,
        evidence_path=external_pilot_evidence_path,
        review_receipt_path=external_pilot_review_receipt_path,
        expected_release=expected_release,
    )
    pilot = verified_pilot.evidence if verified_pilot is not None else None
    assessment = assess_empirical_readiness(
        study_bundle,
        verified_pilot,
        canonical_benchmark,
        expected_release,
    )
    result: dict[str, object] = asdict(assessment)
    result["canonical_benchmark_digest"] = canonical_benchmark.benchmark_digest
    result["study_report_digest"] = (
        study_bundle.report.report_digest if study_bundle is not None else None
    )
    result["study_bundle_files_verified"] = (
        study_bundle.file_count if study_bundle is not None else 0
    )
    result["study_bundle_bytes_verified"] = (
        study_bundle.total_bytes if study_bundle is not None else 0
    )
    result["study_registration_record_sha256"] = (
        study_bundle.registration_record_sha256 if study_bundle is not None else None
    )
    registration_receipt = (
        study_bundle.registration_review_receipt if study_bundle is not None else None
    )
    result["study_registration_review_receipt_digest"] = (
        registration_receipt.review_receipt_digest if registration_receipt is not None else None
    )
    result["study_registration_review_state"] = (
        "operator_attested"
        if assessment.study_registration_evidence_verified and registration_receipt is not None
        else "missing_or_unverified"
    )
    result["study_registration_reviewer_identity_authentication"] = (
        registration_receipt.reviewer_identity_authentication
        if registration_receipt is not None
        else None
    )
    statistical_method_review_receipt = (
        study_bundle.statistical_method_review_receipt if study_bundle is not None else None
    )
    result["study_statistical_method_review_receipt_digest"] = (
        statistical_method_review_receipt.method_review_receipt_digest
        if statistical_method_review_receipt is not None
        else None
    )
    result["study_statistical_method_review_state"] = (
        "qualified_operator_attested"
        if (
            assessment.study_statistical_method_review_verified
            and statistical_method_review_receipt is not None
        )
        else "missing_or_unverified"
    )
    result["study_statistical_method_review_attestation_basis"] = (
        statistical_method_review_receipt.attestation_basis
        if statistical_method_review_receipt is not None
        else None
    )
    result["study_statistical_method_reviewer_identity_authentication"] = (
        statistical_method_review_receipt.reviewer_identity_authentication
        if statistical_method_review_receipt is not None
        else None
    )
    execution_review_receipt = (
        study_bundle.execution_review_receipt if study_bundle is not None else None
    )
    result["study_execution_review_receipt_digest"] = (
        execution_review_receipt.execution_review_receipt_digest
        if execution_review_receipt is not None
        else None
    )
    result["study_execution_review_state"] = (
        "operator_attested"
        if assessment.study_execution_review_verified and execution_review_receipt is not None
        else "missing_or_unverified"
    )
    result["study_execution_reviewer_identity_authentication"] = (
        execution_review_receipt.reviewer_identity_authentication
        if execution_review_receipt is not None
        else None
    )
    result["external_pilot_evidence_digest"] = (
        pilot.pilot_evidence_digest if pilot is not None else None
    )
    result["external_pilot_review_receipt_digest"] = (
        verified_pilot.review_receipt.review_receipt_digest if verified_pilot is not None else None
    )
    result["external_pilot_artifact_manifest_digest"] = (
        verified_pilot.artifact_manifest_digest if verified_pilot is not None else None
    )
    result["external_pilot_bundle_bytes_verified"] = (
        verified_pilot.total_bytes if verified_pilot is not None else 0
    )
    result["external_pilot_independence_review_state"] = (
        "operator_attested" if verified_pilot is not None else "missing_or_unverified"
    )
    result["external_pilot_reviewer_identity_authentication"] = (
        "out_of_band_not_machine_verified" if verified_pilot is not None else None
    )
    result["expected_release"] = expected_release
    return assessment.checkpoint_ready, result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail closed unless validated real-model study and external-pilot artifacts "
            "plus an exact operator-reviewed pilot bundle satisfy the v0.6.6 "
            "empirical checkpoint."
        )
    )
    parser.add_argument(
        "--study-bundle-root",
        required=True,
        type=Path,
        help="Closed real-model study publication directory to verify and replay.",
    )
    parser.add_argument("--external-pilot-bundle-root", required=True, type=Path)
    parser.add_argument(
        "--external-pilot-evidence",
        required=True,
        type=Path,
        help="Portable direct-child filename within --external-pilot-bundle-root.",
    )
    parser.add_argument(
        "--external-pilot-review-receipt",
        required=True,
        type=Path,
        help="Portable direct-child filename within --external-pilot-bundle-root.",
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=CANONICAL_BENCHMARK_PATH,
        help=(
            "Benchmark to validate against the fixed committed canonical artifact and "
            "its packaged mirror."
        ),
    )
    parser.add_argument("--expected-release", required=True)
    args = parser.parse_args(argv)

    try:
        ready, result = check_empirical_readiness(
            args.study_bundle_root,
            args.external_pilot_bundle_root,
            args.external_pilot_evidence,
            args.external_pilot_review_receipt,
            args.benchmark,
            expected_release=args.expected_release,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        # Emit a stable, value-free release-log result instead of copying
        # potentially sensitive validation instance values into CI output.
        ready = False
        result = {
            "blocking_reasons": ["empirical-evidence-invalid-or-unavailable"],
            "checkpoint_ready": False,
            "failure_category": exc.__class__.__name__,
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
