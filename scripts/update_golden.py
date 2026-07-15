from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.authoring.compiler import compile_suite  # noqa: E402
from agent_assure.fixtures.manifest import build_fixture_manifest  # noqa: E402
from agent_assure.reporting.evidence_diff_html import render_evidence_diff_html  # noqa: E402
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

SUITE_YAML = ROOT / "examples" / "prior_auth_synthetic" / "suite.yaml"
SUITE_ROOT = SUITE_YAML.parent
COMPILED_GOLDEN_ROOT = ROOT / "tests" / "golden" / "compiled_suites"
REPORT_GOLDEN_ROOT = ROOT / "tests" / "golden" / "reports"
_DIGEST = "a" * 64

JSON_GOLDENS: dict[Path, Callable[[], Any]] = {
    COMPILED_GOLDEN_ROOT / "prior_auth_synthetic.compiled.json": lambda: compile_suite(
        SUITE_YAML
    ).model_dump(mode="json"),
    COMPILED_GOLDEN_ROOT
    / "prior_auth_synthetic.fixture-manifest.json": lambda: build_fixture_manifest(
        compile_suite(SUITE_YAML),
        SUITE_ROOT,
    ).model_dump(mode="json"),
}
TEXT_GOLDENS: dict[Path, Callable[[], str]] = {
    REPORT_GOLDEN_ROOT / "flagship-evidence-diff.html": lambda: _evidence_diff_html(),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check or update deterministic golden artifacts.")
    parser.add_argument(
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
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(generated, encoding="utf-8", newline="\n")
        return
    if not path.exists():
        failures.append(f"missing golden file: {path.relative_to(ROOT)}")
        return
    existing = path.read_text(encoding="utf-8")
    if existing != generated:
        failures.append(f"golden drift: {path.relative_to(ROOT)}")


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
        target="claim:claim-duration",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        message="fixture-declared material claim has no evidence link",
    )
    candidate_summary = EvaluationSummary(
        runset_id="candidate",
        state=GateState.fail,
        findings=(finding,),
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
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
        artifact_digests=(PacketArtifactDigest(role="evaluation-summary", sha256=_DIGEST),),
        release_manifest=ReleaseArtifactManifest(
            manifest_id="manifest-duration",
            artifacts=(
                ReleaseArtifact(role="compiled-suite", path="compiled.json", sha256=_DIGEST),
                ReleaseArtifact(role="candidate-runset", path="candidate.json", sha256=_DIGEST),
            ),
            environment=EnvironmentInfo(platform="test", python_version="3.11.0"),
        ),
        limitations=("Local deterministic fixture evidence for human review.",),
    )
    return baseline, candidate, comparison, packet


def _runset(runset_id: str, run: AgentRunRecord) -> RunSet:
    return RunSet(
        runset_id=runset_id,
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
