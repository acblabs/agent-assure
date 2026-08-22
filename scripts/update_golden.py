from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.artifact_io import write_text_atomic  # noqa: E402
from agent_assure.authoring.compiler import compile_suite  # noqa: E402
from agent_assure.fixtures.manifest import build_fixture_manifest  # noqa: E402
from agent_assure.io_limits import (  # noqa: E402
    load_json_bytes_bounded,
    read_file_bounded,
    read_text_bounded,
)
from agent_assure.policies.evidence import claim_finding_target  # noqa: E402
from agent_assure.privacy.detectors import (  # noqa: E402
    PRIVACY_PROFILE_DIGEST,
    PRIVACY_PROFILE_ID,
)
from agent_assure.rag.sensitivity import execute_sensitivity_experiment  # noqa: E402
from agent_assure.reporting.evidence_diff_html import render_evidence_diff_html  # noqa: E402
from agent_assure.reporting.sensitivity import (  # noqa: E402
    render_sensitivity_html,
    render_sensitivity_markdown,
    sensitivity_report_json_text,
)
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode  # noqa: E402
from agent_assure.schema.comparison import ComparisonSummary  # noqa: E402
from agent_assure.schema.environment import EnvironmentInfo  # noqa: E402
from agent_assure.schema.evaluation import EvaluationSummary, Finding  # noqa: E402
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest  # noqa: E402
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest  # noqa: E402
from agent_assure.schema.run import (  # noqa: E402
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.sensitivity import (  # noqa: E402
    EvidenceSensitivityExpectedRelation,
    RAGSensitivityReport,
)
from agent_assure.schema.validation import validate_artifact_payload  # noqa: E402

SUITE_YAML = ROOT / "examples" / "prior_auth_synthetic" / "suite.yaml"
SUITE_ROOT = SUITE_YAML.parent
COMPILED_GOLDEN_ROOT = ROOT / "tests" / "golden" / "compiled_suites"
REPORT_GOLDEN_ROOT = ROOT / "tests" / "golden" / "reports"
SENSITIVITY_EXAMPLE_ROOT = ROOT / "examples" / "evidence_sensitivity"
_DIGEST = "a" * 64
MAX_GOLDEN_BYTES = 32 * 1024 * 1024


@cache
def _sensitivity_report(suite_name: str) -> RAGSensitivityReport:
    return execute_sensitivity_experiment(
        suite_path=SENSITIVITY_EXAMPLE_ROOT / suite_name,
        baseline_corpus_dir=SENSITIVITY_EXAMPLE_ROOT / "corpora" / "policy_a",
        counterfactual_corpus_dir=SENSITIVITY_EXAMPLE_ROOT / "corpora" / "policy_b",
        knowledge_contract_path=SENSITIVITY_EXAMPLE_ROOT / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    ).report


JSON_GOLDENS: dict[Path, Callable[[], Any]] = {
    COMPILED_GOLDEN_ROOT / "prior_auth_synthetic.compiled.json": lambda: compile_suite(
        SUITE_YAML
    ).model_dump(mode="json"),
    COMPILED_GOLDEN_ROOT / "prior_auth_synthetic.fixture-manifest.json": lambda: (
        build_fixture_manifest(
            compile_suite(SUITE_YAML),
            SUITE_ROOT,
        ).model_dump(mode="json")
    ),
}
TEXT_GOLDENS: dict[Path, Callable[[], str]] = {
    REPORT_GOLDEN_ROOT / "flagship-evidence-diff.html": lambda: _evidence_diff_html(),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-responsive.json": lambda: (
        sensitivity_report_json_text(_sensitivity_report("responsive_suite.yaml"))
    ),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-responsive.md": lambda: render_sensitivity_markdown(
        _sensitivity_report("responsive_suite.yaml")
    ),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-responsive.html": lambda: render_sensitivity_html(
        _sensitivity_report("responsive_suite.yaml")
    ),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-inertial.json": lambda: sensitivity_report_json_text(
        _sensitivity_report("evidence_inertial_suite.yaml")
    ),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-inertial.md": lambda: render_sensitivity_markdown(
        _sensitivity_report("evidence_inertial_suite.yaml")
    ),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-inertial.html": lambda: render_sensitivity_html(
        _sensitivity_report("evidence_inertial_suite.yaml")
    ),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-reversed.json": lambda: sensitivity_report_json_text(
        _sensitivity_report("evidence_reversed_suite.yaml")
    ),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-reversed.md": lambda: render_sensitivity_markdown(
        _sensitivity_report("evidence_reversed_suite.yaml")
    ),
    REPORT_GOLDEN_ROOT / "evidence-sensitivity-reversed.html": lambda: render_sensitivity_html(
        _sensitivity_report("evidence_reversed_suite.yaml")
    ),
}
LEGACY_REPLAY_GOLDENS: dict[Path, tuple[str, str]] = {
    COMPILED_GOLDEN_ROOT / "prior_auth_synthetic.v0.5.0.compiled.json": (
        "compiled-suite",
        "2bef8d9900846b91952f0a550ddfc9dcaf8e5bfb65a221099b80bc7ac61ddfba",
    ),
    COMPILED_GOLDEN_ROOT / "prior_auth_synthetic.v0.5.0.fixture-manifest.json": (
        "fixture-manifest",
        "afcdeb6f18e211cf38e285fd079a57b7c0f17312112378c4006e987c69d291a4",
    ),
    COMPILED_GOLDEN_ROOT / "prior_auth_synthetic.v0.6.3.compiled.json": (
        "compiled-suite",
        "6611783f3584d9429a044ae9b17b650d43806e831a0f1776e115868ee854ce01",
    ),
    COMPILED_GOLDEN_ROOT / "prior_auth_synthetic.v0.6.3.fixture-manifest.json": (
        "fixture-manifest",
        "2cf427dd565271094480d7fb387b7eee8ea23a570b6be4e530542d3b6a4b9a23",
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check or update deterministic golden artifacts.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="Check committed goldens for drift (the default mode).",
    )
    mode.add_argument(
        "--update-golden",
        action="store_true",
        help="Rewrite golden files instead of checking for drift.",
    )
    args = parser.parse_args()
    failures: list[str] = []
    for path, factory in JSON_GOLDENS.items():
        _check_or_update_golden(
            path,
            _json_text(factory()),
            update=args.update_golden,
            failures=failures,
        )
    for path, factory in TEXT_GOLDENS.items():
        _check_or_update_golden(
            path,
            factory(),
            update=args.update_golden,
            failures=failures,
        )
    for path, (artifact_kind, expected_sha256) in LEGACY_REPLAY_GOLDENS.items():
        _check_legacy_replay_golden(
            path,
            artifact_kind=artifact_kind,
            expected_sha256=expected_sha256,
            failures=failures,
        )
    if failures:
        for failure in failures:
            print(f"golden-check: {failure}", file=sys.stderr)
        print(
            "golden-check: run scripts/update_golden.py --update-golden intentionally",
            file=sys.stderr,
        )
        return 1
    action = "updated" if args.update_golden else "ok"
    print(f"golden-check: {action}")
    return 0


def _json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _check_or_update_golden(
    path: Path,
    generated: str,
    *,
    update: bool,
    failures: list[str],
) -> None:
    if update:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            metadata = None
        if metadata is not None and (
            path.is_symlink()
            or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
            or not stat.S_ISREG(metadata.st_mode)
        ):
            failures.append(f"unsafe golden destination: {path.relative_to(ROOT)}")
            return
        try:
            write_text_atomic(path, generated)
        except OSError as exc:
            failures.append(f"unsafe golden destination: {path.relative_to(ROOT)}: {exc}")
        return
    try:
        existing = read_text_bounded(
            path,
            max_bytes=MAX_GOLDEN_BYTES,
            label="golden artifact",
        )
    except FileNotFoundError:
        failures.append(f"missing golden file: {path.relative_to(ROOT)}")
        return
    except (OSError, UnicodeError, ValueError) as exc:
        failures.append(f"unsafe golden file: {path.relative_to(ROOT)} ({exc})")
        return
    if existing != generated:
        failures.append(f"golden drift: {path.relative_to(ROOT)}")


def _check_legacy_replay_golden(
    path: Path,
    *,
    artifact_kind: str,
    expected_sha256: str,
    failures: list[str],
) -> None:
    """Keep released replay evidence immutable and exercise its frozen schema."""
    try:
        loaded = read_file_bounded(
            path,
            max_bytes=MAX_GOLDEN_BYTES,
            label="legacy replay golden",
        )
    except FileNotFoundError:
        failures.append(f"missing legacy replay golden: {path.relative_to(ROOT)}")
        return
    except (OSError, ValueError) as exc:
        failures.append(f"unsafe legacy replay golden: {path.relative_to(ROOT)} ({exc})")
        return
    raw = loaded.data
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        failures.append(f"legacy replay golden drift: {path.relative_to(ROOT)}")
        return
    try:
        payload = load_json_bytes_bounded(
            raw,
            max_bytes=MAX_GOLDEN_BYTES,
            label="legacy replay golden",
        )
        validation_path = validate_artifact_payload(payload, artifact_kind)
        if validation_path != "frozen-jsonschema":
            raise ValueError(f"unexpected validation path: {validation_path}")
    except Exception as exc:
        failures.append(f"legacy replay golden is invalid: {path.relative_to(ROOT)} ({exc})")


def _evidence_diff_html() -> str:
    baseline, candidate, comparison, packet = _evidence_diff_artifacts()
    return render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        packet=packet,
        artifact_paths={
            "baseline run set": "baseline.runset.json",
            "candidate run set": "candidate.runset.json",
            "evidence packet": "evidence-packet.json",
        },
    )


def _evidence_diff_artifacts() -> tuple[RunSet, RunSet, ComparisonSummary, EvidencePacket]:
    case_id = "shared-source-multi-claim"
    baseline = _runset(
        "baseline",
        _run(
            case_id,
            evidence_refs=(
                EvidenceRef(
                    ref_id="evidence-duration",
                    source_id="guideline-duration",
                    claim_ids=("claim-duration",),
                ),
            ),
        ),
    )
    candidate = _runset("candidate", _run(case_id, evidence_refs=()))
    finding = Finding(
        finding_id="finding-duration",
        case_id=case_id,
        control_id="material_claims_have_evidence",
        target=claim_finding_target("claim-duration"),
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        message=(
            "fixture-declared material claim has no paired reference and "
            "content-addressed evidence item link"
        ),
    )
    candidate_summary = EvaluationSummary(
        runset_id="candidate",
        runset_digest="b" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(finding,),
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="a" * 64,
        candidate_runset_digest="b" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.new_failure,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.fail,
        verdict_findings=(ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value,),
    )
    packet = EvidencePacket(
        packet_id="packet-duration",
        interpretation=("Candidate omitted a material evidence link.",),
        evaluation=candidate_summary,
        comparison=comparison,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256=_DIGEST),
            PacketArtifactDigest(role="comparison-summary", sha256=_DIGEST),
        ),
        release_manifest=ReleaseArtifactManifest(
            manifest_id="manifest-duration",
            artifacts=(
                ReleaseArtifact(role="compiled-suite", path="compiled.json", sha256=_DIGEST),
                ReleaseArtifact(role="candidate-runset", path="candidate.json", sha256=_DIGEST),
                ReleaseArtifact(
                    role="evaluation-summary",
                    path="evaluation-summary.json",
                    sha256=_DIGEST,
                ),
                ReleaseArtifact(
                    role="comparison-summary",
                    path="comparison-summary.json",
                    sha256=_DIGEST,
                ),
            ),
            environment=EnvironmentInfo(platform="test", python_version="3.11.0"),
        ),
        limitations=("Local deterministic fixture evidence for human review.",),
    )
    return baseline, candidate, comparison, packet


def _runset(runset_id: str, run: AgentRunRecord) -> RunSet:
    return RunSet(
        runset_id=runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="prior-auth-synthetic",
        suite_version="0.1.0",
        suite_digest=_DIGEST,
        fixture_manifest_digest=_DIGEST,
        runs=(run,),
    )


def _run(
    case_id: str,
    *,
    evidence_refs: tuple[EvidenceRef, ...],
    link_claims: bool = True,
) -> AgentRunRecord:
    claim_evidence_links = (
        (
            ClaimEvidenceLink(
                claim_id="claim-duration",
                evidence_ref_id="evidence-duration",
            ),
        )
        if link_claims and any(ref.ref_id == "evidence-duration" for ref in evidence_refs)
        else ()
    )
    return AgentRunRecord(
        run_id=f"run-{case_id}",
        case_id=case_id,
        pipeline_id="demo",
        recommendation="approve",
        outcome="approve",
        input_summary="redacted fixture input",
        output_summary="redacted fixture output",
        claims=(ClaimRecord(claim_id="claim-duration"),),
        evidence_refs=evidence_refs,
        evidence_items=tuple(
            EvidenceItem(
                ref_id=ref.ref_id,
                source_id=ref.source_id,
                content_digest=_DIGEST,
            )
            for ref in evidence_refs
        ),
        claim_evidence_links=claim_evidence_links,
        tools=("benefit-policy-lookup",),
    )


if __name__ == "__main__":
    raise SystemExit(main())
