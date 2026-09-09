from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Literal

import typer
from pydantic import Field, ValidationError, field_validator
from rich.console import Console

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.cli._publication import (
    bounded_model_json,
    ensure_finalize_paths,
    publish_finalize_outputs,
)
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    loads_json_bounded,
    read_text_bounded_from_filesystem_root,
)
from agent_assure.onboarding.diagnostics import bounded_error, display_path
from agent_assure.pilot_bundle import (
    build_external_pilot_review_receipt,
    load_external_pilot_review_inputs,
    load_verified_external_pilot_bundle,
)
from agent_assure.release_evidence import (
    core_release_roles_for_schema_version,
    load_digest_replay,
    verify_digest_replay,
)
from agent_assure.reporting.text_safety import sanitize_display_text
from agent_assure.rooted_io import portable_relative_path_parts
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import (
    STRICT_RFC3339_TIMESTAMP_PATTERN,
    MachineIdentifier,
    coerce_tuple,
)
from agent_assure.schema.pilot import ExternalPilotEvidence, PilotWorkflowDispatchInput

app = typer.Typer(help="Release evidence utilities.")
pilot_app = typer.Typer(help="Finalize externally operated pilot evidence.")
app.add_typer(pilot_app, name="pilot")
console = Console()


class _PilotWorkflowRunTemplate(StrictModel):
    stage: Literal["capture", "finalize"]
    run_url: str = Field(min_length=1, max_length=512)
    run_attempt: int = Field(ge=1)
    run_head_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    trusted_workflow_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    execution_source_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    workflow_path: str = Field(min_length=1, max_length=255)
    run_head_workflow_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    trusted_workflow_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    workflow_bytes_match_trusted_revision: Literal[True]
    public_inputs: tuple[PilotWorkflowDispatchInput, ...] = Field(min_length=1, max_length=32)

    @field_validator("public_inputs", mode="before")
    @classmethod
    def _coerce_public_inputs(cls, value: object) -> object:
        return coerce_tuple(value)


class _PilotReviewTemplate(StrictModel):
    receipt_id: MachineIdentifier
    reviewer_pseudonym: MachineIdentifier
    manual_approval_is_trust_root: Literal[True]
    reviewer_independent_of_pilot_execution: Literal[True]
    reviewer_independence_rationale: str = Field(min_length=1, max_length=2_048)
    environment_control_evidence_reviewed: Literal[True]
    artifact_inventory_reviewed: Literal[True]
    tested_distribution_provenance_reviewed: Literal[True]
    command_input_bindings_reviewed: Literal[True]
    execution_time_input_content_digests_reviewed: Literal[True]
    input_semantic_identities_reviewed: Literal[True]
    complete_bundle_publication_consent_reviewed: Literal[True]
    capture_workflow_run: _PilotWorkflowRunTemplate
    finalize_workflow_run: _PilotWorkflowRunTemplate
    run_head_shas_reviewed: Literal[True]
    workflow_run_urls_reviewed: Literal[True]
    trusted_workflow_bytes_reviewed: Literal[True]
    execution_source_pins_reviewed: Literal[True]
    public_workflow_inputs_reviewed: Literal[True]
    friction_and_remediation_disposition_reviewed: Literal[True]
    friction_category_and_remediation_bindings_reviewed: Literal[True]
    privacy_boundary_reviewed: Literal[True]
    review_outcome: Literal["approved_for_empirical_checkpoint"]
    reviewed_at: str = Field(pattern=STRICT_RFC3339_TIMESTAMP_PATTERN)


@app.callback()
def callback() -> None:
    """Verify release evidence digests."""


@pilot_app.command("finalize")
def finalize_pilot_evidence(
    template_path: Annotated[
        Path,
        typer.Option(
            "--template",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="External-pilot evidence authoring payload in JSON or YAML.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=True,
            dir_okay=False,
            help="Canonical self-digested external-pilot evidence JSON.",
        ),
    ],
) -> None:
    """Finalize a bounded pilot-evidence template without hand-computed digests."""

    try:
        ensure_finalize_paths(
            inputs=(template_path,),
            outputs=(out,),
            config_output_pairs=(),
        )
        values = _load_authoring_mapping(
            template_path,
            label="external pilot evidence template",
        )
        values.pop("pilot_evidence_digest", None)
        evidence = ExternalPilotEvidence.build(**values)
        text = bounded_model_json(evidence, label="external pilot evidence")
        if ExternalPilotEvidence.model_validate_json(text) != evidence:
            raise RuntimeError("finalized external pilot evidence did not round-trip exactly")
        lock_root = _pilot_publication_lock_root(
            out.parent,
            label="pilot evidence output directory",
        )
        publish_finalize_outputs(
            ((out, text, "external pilot evidence"),),
            lock_root=lock_root,
        )
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"external pilot evidence finalization failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("external pilot evidence finalization failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"pilot id: {sanitize_display_text(evidence.pilot_id)}")
    typer.echo(f"pilot evidence digest: {evidence.pilot_evidence_digest}")
    typer.echo(f"finalized pilot evidence: {display_path(out)}")


@pilot_app.command("review")
def review_pilot_bundle(
    bundle_root: Annotated[
        Path,
        typer.Option(
            "--bundle-root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Closed directory containing pilot evidence and declared artifacts.",
        ),
    ],
    evidence_path: Annotated[
        str,
        typer.Option(
            "--evidence",
            help="Canonical bundle-root child naming the finalized evidence JSON.",
        ),
    ] = "external-pilot-evidence.json",
    template_path: Annotated[
        Path,
        typer.Option(
            "--template",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Human reviewer attestations in JSON or YAML; keep outside the bundle.",
        ),
    ] = Path("external-pilot-independence-review.yaml"),
    out: Annotated[
        str,
        typer.Option(
            "--out",
            help="Canonical bundle-root child for the finalized review receipt JSON.",
        ),
    ] = "external-pilot-independence-review.json",
) -> None:
    """Derive exact bundle bindings and finalize a human review receipt."""

    try:
        evidence_name = _direct_child_name(evidence_path, label="pilot evidence")
        output_name = _direct_child_name(out, label="pilot review receipt")
        if evidence_name.casefold() == output_name.casefold():
            raise ValueError("pilot evidence and review receipt paths must be distinct")
        output_path = bundle_root / output_name
        evidence_file = bundle_root / evidence_name
        lock_root = _pilot_publication_lock_root(
            bundle_root,
            label="pilot bundle directory",
        )
        ensure_finalize_paths(
            inputs=(template_path, evidence_file),
            outputs=(output_path,),
            config_output_pairs=(),
        )
        review_inputs = load_external_pilot_review_inputs(
            bundle_root,
            evidence_path=evidence_name,
            review_receipt_path=output_name,
        )
        authored = _PilotReviewTemplate.model_validate(
            _load_authoring_mapping(
                template_path,
                label="external pilot independence review template",
            )
        )
        receipt = build_external_pilot_review_receipt(
            review_inputs,
            **authored.model_dump(mode="python", warnings="error"),
        )
        text = bounded_model_json(
            receipt,
            label="external pilot independence review receipt",
        )
        if type(receipt).model_validate_json(text) != receipt:
            raise RuntimeError("finalized pilot review receipt did not round-trip exactly")
        publish_finalize_outputs(
            ((output_path, text, "external pilot independence review receipt"),),
            lock_root=lock_root,
        )
        verified = load_verified_external_pilot_bundle(
            bundle_root,
            evidence_path=evidence_name,
            review_receipt_path=output_name,
            expected_release=review_inputs.evidence.subject.implementation_version,
        )
        if verified.review_receipt != receipt:
            raise RuntimeError("published pilot review receipt did not verify exactly")
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"external pilot review finalization failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("external pilot review finalization failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"pilot id: {sanitize_display_text(review_inputs.evidence.pilot_id)}")
    typer.echo(f"pilot evidence file sha256: {review_inputs.pilot_evidence_file_sha256}")
    typer.echo(f"artifact manifest digest: {review_inputs.artifact_manifest_digest}")
    typer.echo(f"review receipt digest: {receipt.review_receipt_digest}")
    typer.echo(f"finalized pilot review receipt: {display_path(output_path)}")


@app.command("replay")
def replay(
    digest_replay: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, help="Release digest replay JSON."),
    ],
    artifact_root: Annotated[
        Path,
        typer.Option(
            "--artifact-root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            help="Root for relative artifact paths in the replay file.",
        ),
    ] = Path("."),
    require_role: Annotated[
        list[str] | None,
        typer.Option("--require-role", help="Artifact role that must be listed."),
    ] = None,
    expect_commit: Annotated[
        str | None,
        typer.Option("--expect-commit", help="Expected source commit for this replay file."),
    ] = None,
    expect_ref: Annotated[
        str | None,
        typer.Option("--expect-ref", help="Expected source ref for this replay file."),
    ] = None,
    require_current_commit: Annotated[
        bool,
        typer.Option(
            "--require-current-commit/--no-require-current-commit",
            help="Require the current git checkout to match the replay source_commit.",
        ),
    ] = False,
    require_core: Annotated[
        bool,
        typer.Option(
            "--require-core/--no-require-core",
            help="Require the core artifact roles defined by the replay schema version.",
        ),
    ] = True,
) -> None:
    try:
        replay_artifact = load_digest_replay(digest_replay)
        core_roles = (
            core_release_roles_for_schema_version(replay_artifact.schema_version)
            if require_core
            else ()
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    required_roles = tuple(require_role or ())
    required_roles = (*core_roles, *required_roles)
    verification = verify_digest_replay(
        replay_artifact,
        artifact_root=artifact_root,
        required_roles=required_roles,
        expect_commit=expect_commit,
        expect_ref=expect_ref,
        require_current_commit=require_current_commit,
    )
    if not verification.ok:
        payload = {
            "artifact_kind": replay_artifact.artifact_kind,
            "exit_code": 1,
            "findings": [
                {
                    "role": finding.role,
                    "path": finding.path,
                    "expected": finding.expected,
                    "actual": finding.actual,
                    "message": finding.message,
                }
                for finding in verification.findings
            ],
        }
        typer.echo(json.dumps(payload, sort_keys=True))
        raise typer.Exit(1)
    console.print(
        "release digest replay verified: "
        f"{len(replay_artifact.artifacts)} artifacts from {digest_replay}"
    )


def _load_authoring_mapping(path: Path, *, label: str) -> dict[str, object]:
    text = read_text_bounded_from_filesystem_root(
        path,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=label,
    )
    suffix = path.suffix.lower()
    if suffix == ".json":
        payload = loads_json_bounded(text, label=label)
    elif suffix in {".yaml", ".yml"}:
        payload = safe_load_yaml_text(text, label=label)
    else:
        raise ValueError(f"{label} must use .json, .yaml, or .yml")
    if not isinstance(payload, dict):
        raise TypeError(f"{label} must be a mapping")
    return payload


def _direct_child_name(value: str, *, label: str) -> str:
    parts = portable_relative_path_parts(value)
    if len(parts) != 1 or parts[0] != value:
        raise ValueError(f"{label} path must be one canonical portable bundle-root child")
    return value


def _pilot_publication_lock_root(target_directory: Path, *, label: str) -> Path:
    # Keep persistent locks outside closed inventories without silently
    # escaping above the directory from which the operator invoked the CLI.
    try:
        resolved_target = target_directory.resolve(strict=True)
        resolved_working_directory = Path.cwd().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} cannot be safely resolved for publication locking") from exc

    try:
        resolved_working_directory.relative_to(resolved_target)
    except ValueError:
        pass
    else:
        raise ValueError(
            f"{label} cannot be the current working directory or its ancestor; "
            "use a dedicated child directory so the persistent publication lock "
            "is not written above the working directory"
        )

    lock_root = resolved_target.parent
    if lock_root == Path(lock_root.anchor):
        raise ValueError(f"{label} must have a non-root parent for persistent publication locking")
    return lock_root


__all__ = ["app"]
