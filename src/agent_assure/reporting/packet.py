from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.privacy.redaction import redact_packet_payload, redact_text
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest, PacketArtifactRole
from agent_assure.schema.release import ReleaseArtifactManifest
from agent_assure.schema.usage import UsageSummary
from agent_assure.schema.validation import load_json

DEFAULT_PACKET_LIMITATIONS = (
    "evidence packets summarize deterministic fixture-mode results; they are not "
    "signatures, attestations, safety certifications, compliance certifications, "
    "or live model-quality evidence",
)
DEFAULT_INTERPRETATION = (
    "Start with candidate_vs_expectations: pass means no blocking deterministic "
    "finding under the selected gate profile; fail means at least one expectation, "
    "policy, invariant, or configured gate failed.",
    "If a comparison summary is present, fixture_equivalence_state must be pass "
    "before interpreting candidate-to-baseline changes.",
    "Artifact digests and release-manifest digests are reproducibility anchors "
    "over local files; they are not signatures or external attestations.",
    "Not-evaluated capabilities are explicit scope boundaries, not evidence that "
    "the capability passed.",
    "If a usage summary is present, treat it as measured usage and declared "
    "estimated cost evidence for human review, not business impact evidence.",
)


def load_evaluation_summary(path: Path) -> EvaluationSummary:
    return EvaluationSummary.model_validate(load_json(path))


def load_comparison_summary(path: Path) -> ComparisonSummary:
    return ComparisonSummary.model_validate(load_json(path))


def build_evidence_packet(
    evaluation: EvaluationSummary,
    *,
    comparison: ComparisonSummary | None = None,
    environment: EnvironmentInfo | None = None,
    release_manifest: ReleaseArtifactManifest | None = None,
    usage_summary: UsageSummary | None = None,
    artifact_digests: tuple[PacketArtifactDigest, ...] = (),
    packet_id: str | None = None,
    interpretation: tuple[str, ...] = DEFAULT_INTERPRETATION,
    limitations: tuple[str, ...] = DEFAULT_PACKET_LIMITATIONS,
) -> EvidencePacket:
    resolved_packet_id = packet_id or _packet_id(
        evaluation,
        comparison=comparison,
        interpretation=interpretation,
        limitations=limitations,
    )
    return EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id=resolved_packet_id,
        interpretation=interpretation,
        evaluation=evaluation,
        comparison=comparison,
        environment=environment,
        release_manifest=release_manifest,
        usage_summary=usage_summary or evaluation.usage_summary,
        artifact_digests=artifact_digests,
        limitations=limitations,
    )


def packet_artifact_digest(
    role: PacketArtifactRole,
    path: Path,
) -> PacketArtifactDigest:
    return PacketArtifactDigest(
        artifact_kind="packet-artifact-digest",
        role=role,
        sha256=_file_sha256(path),
    )


def write_evidence_packet(packet: EvidencePacket, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = redact_packet_payload(packet.model_dump(mode="json"))
    EvidencePacket.model_validate(payload)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def load_evidence_packet(path: Path) -> EvidencePacket:
    return EvidencePacket.model_validate(load_json(path))


def render_evidence_packet_markdown(packet: EvidencePacket) -> str:
    lines = [
        "# Evidence Packet",
        "",
        "## How to Interpret",
        "",
    ]
    lines.extend(f"- {redact_text(item)}" for item in packet.interpretation)
    lines.extend(
        [
            "",
            "## Candidate Summary",
            "",
            f"- Run set: `{packet.evaluation.runset_id}`",
            f"- State: `{packet.evaluation.state.value}`",
            f"- Findings: `{len(packet.evaluation.findings)}`",
            f"- Usage summary: `{_usage_presence(packet.usage_summary)}`",
        ]
    )
    if packet.comparison is not None:
        lines.extend(
            [
                "",
                "## Comparison Summary",
                "",
                f"- Baseline run set: `{packet.comparison.baseline_runset_id}`",
                f"- Candidate run set: `{packet.comparison.candidate_runset_id}`",
                f"- Classification: `{packet.comparison.classification.value}`",
                f"- Fixture equivalence: `{packet.comparison.fixture_equivalence_state.value}`",
            ]
        )
    if packet.environment is not None:
        lines.extend(
            [
                "",
                "## Environment",
                "",
                f"- Platform: `{redact_text(packet.environment.platform)}`",
                f"- Python: `{redact_text(packet.environment.python_version.splitlines()[0])}`",
                f"- Git commit: `{packet.environment.git_commit or '<unknown>'}`",
                f"- Git dirty: `{packet.environment.git_dirty}`",
                f"- Lockfile: `{packet.environment.lockfile_path or '<none>'}`",
                f"- Lockfile digest: `{packet.environment.lockfile_digest or '<none>'}`",
                "- Dependency inventory: "
                f"`{packet.environment.dependency_inventory_path or '<none>'}`",
                "- Dependency inventory digest: "
                f"`{packet.environment.dependency_inventory_digest or '<none>'}`",
                f"- Installed packages: `{len(packet.environment.installed_packages)}`",
            ]
        )
    if packet.release_manifest is not None:
        lines.extend(["", "## Release Artifact Manifest", ""])
        lines.extend(
            f"- `{artifact.role}` `{redact_text(artifact.path)}` `{artifact.sha256}`"
            for artifact in packet.release_manifest.artifacts
        )
    lines.extend(["", "## Measured Usage", ""])
    lines.extend(_usage_summary_lines(packet.usage_summary))
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {redact_text(limitation)}" for limitation in packet.limitations)
    return "\n".join(lines) + "\n"


def write_evidence_packet_markdown(packet: EvidencePacket, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_evidence_packet_markdown(packet), encoding="utf-8", newline="\n")


def _packet_id(
    evaluation: EvaluationSummary,
    *,
    comparison: ComparisonSummary | None,
    interpretation: tuple[str, ...],
    limitations: tuple[str, ...],
) -> str:
    payload = {
        "interpretation": interpretation,
        "evaluation": _summary_for_packet_id(evaluation),
        "comparison": _summary_for_packet_id(comparison) if comparison is not None else None,
        "limitations": limitations,
    }
    return f"packet-{sha256_hexdigest(redact_packet_payload(payload))[:16]}"


def _summary_for_packet_id(
    summary: EvaluationSummary | ComparisonSummary,
) -> dict[str, object]:
    return summary.model_dump(mode="json", exclude={"environment"})


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _usage_summary_lines(summary: UsageSummary | None) -> list[str]:
    if summary is None:
        return ["- measured usage: `not_observed`"]
    lines = [
        f"- total tokens: `{_observed_int(summary.total_tokens)}`",
        f"- tool calls: `{_observed_int(summary.total_tool_calls)}`",
        f"- retries: `{_observed_int(summary.total_retries)}`",
        f"- latency ms: `{_observed_int(summary.total_latency_ms)}`",
        (
            "- declared estimated cost: "
            f"`{_observed_int(summary.estimated_cost_microusd)}` micro-USD "
            f"`{summary.currency}`"
        ),
    ]
    lines.extend(f"- limitation: {redact_text(limitation)}" for limitation in summary.limitations)
    return lines


def _observed_int(value: int | None) -> str:
    if value is None:
        return "not_observed"
    return str(value)


def _usage_presence(summary: UsageSummary | None) -> str:
    if summary is None:
        return "not_observed"
    return "observed"
