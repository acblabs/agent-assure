"""Offline authoring, binding, and analysis commands for real-model studies."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, TypeVar

import typer
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.cli._publication import (
    bounded_model_json,
    ensure_finalize_paths,
    ensure_output_does_not_alias_inputs,
    publish_finalize_outputs,
    reject_inline_environment_for_finalization,
)
from agent_assure.evaluation.evaluator import load_runset_with_size
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
    loads_json_bounded,
    read_bytes_bounded_from_filesystem_root,
)
from agent_assure.live.config import LiveRunConfig, load_live_run_config
from agent_assure.live.runner import calculate_live_provider_input_manifest_digest
from agent_assure.onboarding.diagnostics import bounded_error, display_path
from agent_assure.privacy.persistence import assert_persisted_payload_safe
from agent_assure.rag.repeated_sensitivity import (
    load_repeated_sensitivity_protocol,
    load_repeated_sensitivity_protocol_with_size,
)
from agent_assure.reporting.study import (
    StudyOutputConflictError,
    StudyPrivacyError,
    write_real_model_study_artifacts,
)
from agent_assure.reporting.text_safety import sanitize_display_text
from agent_assure.rooted_io import portable_relative_path_parts
from agent_assure.schema.base import StrictModel
from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.common import MachineIdentifier, coerce_tuple
from agent_assure.schema.stochastic_sensitivity import (
    RepeatedEvidenceSensitivityProtocol,
)
from agent_assure.schema.study import (
    RealModelStudyManifest,
    StudyExecutionReviewReceipt,
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
)
from agent_assure.schema.validation import (
    load_validated_artifact_payload_with_size,
    project_validated_artifact_payload,
)
from agent_assure.study.analysis import (
    StudyConditionEvidence,
    analyze_real_model_study,
    bind_study_manifest_to_live_config,
    derive_study_observed_execution_provenance,
    validate_study_manifest_inputs,
)
from agent_assure.study_artifact_serialization import published_model_json_bytes
from agent_assure.study_bundle import load_and_validate_study_bundle
from agent_assure.study_execution_review import build_study_execution_review_receipt
from agent_assure.study_limits import MAX_STUDY_BUNDLE_TOTAL_BYTES
from agent_assure.study_method_review import (
    build_study_statistical_method_review_receipt,
)
from agent_assure.study_registration import validate_study_registration

app = typer.Typer(help="Preregistered real-model study authoring and offline analysis.")
ArtifactModelT = TypeVar("ArtifactModelT", bound=BaseModel)


@dataclass(slots=True)
class _StudyInputByteBudget:
    """Bound retained descriptor inputs and each next read as one transaction."""

    remaining: int = MAX_STUDY_BUNDLE_TOTAL_BYTES

    def next_read_limit(self, per_file_limit: int) -> int:
        if self.remaining <= 0:
            raise ValueError("study evidence inputs exceed the maximum aggregate size")
        return min(per_file_limit, self.remaining)

    def consume_bytes(self, size: int) -> None:
        if size < 0 or size > self.remaining:
            raise ValueError("study evidence inputs exceed the maximum aggregate size")
        self.remaining -= size


class _StudyEvidenceCondition(StrictModel):
    condition_id: MachineIdentifier
    registered_protocol: str = Field(min_length=1, max_length=1_024)
    source_run_directory: str | None = Field(default=None, max_length=1_024)

    @field_validator("registered_protocol", "source_run_directory")
    @classmethod
    def _validate_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return "/".join(portable_relative_path_parts(value))


class _StudyEvidenceDescriptor(StrictModel):
    schema_name: Literal["real-model-study-evidence-input/v1"] = (
        "real-model-study-evidence-input/v1"
    )
    registration_record: str = Field(min_length=1, max_length=1_024)
    registration_review_receipt: str = Field(min_length=1, max_length=1_024)
    statistical_method_review_receipt: str | None = Field(
        default=None,
        max_length=1_024,
    )
    execution_review_receipt: str | None = Field(default=None, max_length=1_024)
    conditions: tuple[_StudyEvidenceCondition, ...] = Field(min_length=1, max_length=64)

    @field_validator(
        "registration_record",
        "registration_review_receipt",
        "statistical_method_review_receipt",
        "execution_review_receipt",
    )
    @classmethod
    def _validate_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return "/".join(portable_relative_path_parts(value))

    @field_validator("conditions", mode="before")
    @classmethod
    def _coerce_conditions(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_conditions(self) -> _StudyEvidenceDescriptor:
        condition_ids = tuple(item.condition_id for item in self.conditions)
        if condition_ids != tuple(sorted(set(condition_ids))):
            raise ValueError("study evidence conditions must be unique and sorted by condition_id")
        return self


class _StudyRegistrationReviewTemplate(StrictModel):
    receipt_id: MachineIdentifier
    reviewed_at_utc: str = Field(min_length=1, max_length=64)
    reviewer_pseudonym: MachineIdentifier
    registration_record_coverage_confirmed: Literal[True]
    pre_observation_ordering_confirmed: Literal[True]
    registration_reference_resolved: Literal[True]
    registration_record_digest_match_confirmed: Literal[True]
    registration_record_immutability_confirmed: Literal[True]


class _StudyExecutionReviewTemplate(StrictModel):
    receipt_id: MachineIdentifier
    reviewed_at_utc: str = Field(min_length=1, max_length=64)
    reviewer_pseudonym: MachineIdentifier
    reviewer_independent_of_execution: Literal[True]
    reviewer_independence_rationale: str = Field(min_length=1, max_length=4_096)
    provider_log_and_account_review_confirmed: Literal[True]
    exhaustive_attempt_failure_retry_accounting_confirmed: Literal[True]
    provider_response_id_matches_confirmed: Literal[True]
    exact_runset_artifact_digest_matches_confirmed: Literal[True]


class _StudyStatisticalMethodReviewTemplate(StrictModel):
    receipt_id: MachineIdentifier
    reviewed_at_utc: str = Field(min_length=1, max_length=64)
    reviewer_pseudonym: MachineIdentifier
    reviewer_statistical_qualification_confirmed: Literal[True]
    reviewer_qualification_basis: str = Field(min_length=32, max_length=4_096)
    reviewer_independent_of_design_execution_and_analysis: Literal[True]
    reviewer_independence_rationale: str = Field(min_length=32, max_length=4_096)
    benchmark_cluster_assignments_reviewed: Literal[True]
    independence_and_exchangeability_assumptions_reviewed: Literal[True]
    sampling_frame_and_estimand_reviewed: Literal[True]
    multiplicity_and_interval_method_reviewed: Literal[True]
    power_and_decision_boundary_reachability_reviewed: Literal[True]
    negative_control_design_reviewed: Literal[True]


@app.callback()
def callback() -> None:
    """Run offline real-model study workflows."""


@app.command("input-commitment")
def input_commitment(
    compiled_suite_path: Annotated[
        Path,
        typer.Option(
            "--compiled-suite",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Compiled suite containing the frozen case inputs.",
        ),
    ],
    config_path: Annotated[
        Path,
        typer.Option(
            "--config",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Unbound live arm config whose resource paths will be snapshotted.",
        ),
    ],
) -> None:
    """Compute the exact provider-input commitment without dispatch."""

    try:
        compiled = load_compiled_suite(compiled_suite_path)
        config = load_live_run_config(config_path)
        digest = calculate_live_provider_input_manifest_digest(
            compiled,
            config,
            config_dir=config_path.parent,
        )
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"study input commitment failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("study input commitment failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"provider input manifest digest: {digest}")


@app.command("review-registration")
def review_registration(
    manifest_path: Annotated[
        Path,
        typer.Option(
            "--manifest",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Final self-digested study manifest JSON.",
        ),
    ],
    record_path: Annotated[
        Path,
        typer.Option(
            "--record",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Exact UTF-8 JSON preregistration record committed by the manifest.",
        ),
    ],
    template_path: Annotated[
        Path,
        typer.Option(
            "--template",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Human reviewer attestation in JSON or YAML.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=True,
            dir_okay=False,
            help="Canonical self-digested registration-review receipt JSON.",
        ),
    ] = Path("study-registration-review.json"),
) -> None:
    """Build a bounded pre-execution receipt for exact registration bytes."""

    try:
        ensure_finalize_paths(
            inputs=(manifest_path, record_path, template_path),
            outputs=(out,),
            config_output_pairs=(),
        )
        manifest = _load_artifact(
            manifest_path,
            kind="real-model-study-manifest",
            model=RealModelStudyManifest,
        )
        record_bytes = read_bytes_bounded_from_filesystem_root(
            record_path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="study registration record",
        )
        authored = _StudyRegistrationReviewTemplate.model_validate(
            _load_authoring_mapping(
                template_path,
                label="study registration review template",
            )
        )
        receipt = StudyRegistrationReviewReceipt.build(
            **authored.model_dump(mode="python", warnings="error"),
            study_id=manifest.study_id,
            study_manifest_digest=manifest.manifest_digest,
            registration_method=manifest.registration.method,
            registration_reference_id=manifest.registration.reference_id,
            registration_evidence_sha256=manifest.registration.evidence_digest,
            registered_at_utc=manifest.registration.registered_at_utc,
        )
        validate_study_registration(
            manifest=manifest,
            registration_record_bytes=record_bytes,
            review_receipt=receipt,
        )
        text = _safe_bounded_model_json(
            receipt,
            label="study registration review receipt",
        )
        publish_finalize_outputs(((out, text, "study registration review receipt"),))
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"study registration review failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("study registration review failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"study id: {sanitize_display_text(manifest.study_id)}")
    typer.echo(f"registration record digest: {manifest.registration.evidence_digest}")
    typer.echo(f"review receipt digest: {receipt.review_receipt_digest}")
    typer.echo(f"registration review receipt: {display_path(out)}")


@app.command("review-statistics")
def review_statistics(
    manifest_path: Annotated[
        Path,
        typer.Option(
            "--manifest",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Final self-digested study manifest JSON.",
        ),
    ],
    benchmark_path: Annotated[
        Path,
        typer.Option(
            "--benchmark",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Exact benchmark JSON bound by the study manifest.",
        ),
    ],
    protocol_specs: Annotated[
        list[str] | None,
        typer.Option(
            "--protocol",
            metavar="CONDITION_ID=PATH",
            help="Frozen repeated protocol for one condition. Repeat for every condition.",
        ),
    ] = None,
    template_path: Annotated[
        Path,
        typer.Option(
            "--template",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Qualified independent statistical-review attestation in JSON or YAML.",
        ),
    ] = Path("study-statistical-method-review.yaml"),
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=True,
            dir_okay=False,
            help="Canonical self-digested statistical-method review receipt JSON.",
        ),
    ] = Path("study-statistical-method-review.json"),
) -> None:
    """Bind qualified pre-execution statistical approval to the exact design."""

    try:
        protocol_paths = _parse_condition_path_specs(
            protocol_specs,
            label="statistical-review protocol",
        )
        ensure_finalize_paths(
            inputs=(
                manifest_path,
                benchmark_path,
                template_path,
                *protocol_paths.values(),
            ),
            outputs=(out,),
            config_output_pairs=(),
        )
        manifest = _load_artifact(
            manifest_path,
            kind="real-model-study-manifest",
            model=RealModelStudyManifest,
        )
        benchmark = _load_artifact(
            benchmark_path,
            kind="process-equivalence-benchmark",
            model=ProcessEquivalenceBenchmarkManifest,
        )
        protocols = {
            condition_id: load_repeated_sensitivity_protocol(path)
            for condition_id, path in protocol_paths.items()
        }
        validate_study_manifest_inputs(manifest, benchmark, protocols)
        authored = _StudyStatisticalMethodReviewTemplate.model_validate(
            _load_authoring_mapping(
                template_path,
                label="study statistical-method review template",
            )
        )
        receipt = build_study_statistical_method_review_receipt(
            manifest=manifest,
            benchmark=benchmark,
            protocols=protocols,
            **authored.model_dump(mode="python", warnings="error"),
        )
        text = _safe_bounded_model_json(
            receipt,
            label="study statistical-method review receipt",
        )
        publish_finalize_outputs(((out, text, "study statistical-method review receipt"),))
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"study statistical-method review failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("study statistical-method review failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"study id: {sanitize_display_text(manifest.study_id)}")
    typer.echo(f"manifest digest: {manifest.manifest_digest}")
    typer.echo(f"method review receipt digest: {receipt.method_review_receipt_digest}")
    typer.echo(f"statistical-method review receipt: {display_path(out)}")


@app.command("review-execution")
def review_execution(
    bundle_path: Annotated[
        Path,
        typer.Option(
            "--bundle",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Closed replayed study bundle produced before execution review.",
        ),
    ],
    template_path: Annotated[
        Path,
        typer.Option(
            "--template",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Independent reviewer attestation in JSON or YAML.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=True,
            dir_okay=False,
            help="Canonical self-digested execution-review receipt JSON.",
        ),
    ] = Path("study-execution-review.json"),
) -> None:
    """Review exact replayed provider evidence without mutating its bundle."""

    try:
        ensure_finalize_paths(
            inputs=(template_path,),
            outputs=(out,),
            config_output_pairs=(),
        )
        ensure_output_does_not_alias_inputs(
            out=out,
            inputs=(template_path,),
            input_directories=(bundle_path,),
        )
        bundle = load_and_validate_study_bundle(bundle_path)
        authored = _StudyExecutionReviewTemplate.model_validate(
            _load_authoring_mapping(
                template_path,
                label="study execution review template",
            )
        )
        receipt = build_study_execution_review_receipt(
            manifest=bundle.manifest,
            benchmark=bundle.benchmark,
            protocols=bundle.protocols,
            report=bundle.report,
            evidence=bundle.evidence,
            **authored.model_dump(mode="python", warnings="error"),
        )
        text = _safe_bounded_model_json(
            receipt,
            label="study execution review receipt",
        )
        publish_finalize_outputs(((out, text, "study execution review receipt"),))
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"study execution review failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("study execution review failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"study id: {sanitize_display_text(bundle.manifest.study_id)}")
    typer.echo(f"study report digest: {bundle.report.report_digest}")
    typer.echo(f"execution review receipt digest: {receipt.execution_review_receipt_digest}")
    typer.echo(f"execution review receipt: {display_path(out)}")


@app.command("finalize")
def finalize(
    template_path: Annotated[
        Path,
        typer.Option(
            "--template",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Study-manifest authoring payload in JSON or YAML.",
        ),
    ],
    benchmark_path: Annotated[
        Path,
        typer.Option(
            "--benchmark",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Digest-bound Process-Equivalence Benchmark JSON.",
        ),
    ],
    protocol_specs: Annotated[
        list[str] | None,
        typer.Option(
            "--protocol",
            metavar="CONDITION_ID=PATH",
            help="Frozen repeated protocol for one condition. Repeat for every condition.",
        ),
    ] = None,
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=True,
            dir_okay=False,
            help="Final self-digested study manifest JSON.",
        ),
    ] = Path("real-model-study-manifest.json"),
) -> None:
    """Finalize and validate a study manifest without provider dispatch."""

    try:
        protocol_paths = _parse_condition_path_specs(
            protocol_specs,
            label="study protocol",
        )
        ensure_finalize_paths(
            inputs=(template_path, benchmark_path, *protocol_paths.values()),
            outputs=(out,),
            config_output_pairs=(),
        )
        values = dict(_load_authoring_mapping(template_path, label="study manifest template"))
        for derived_field in (
            "manifest_digest",
            "protocol_set_digest",
            "hypothesis_decision_rule_digest",
        ):
            values.pop(derived_field, None)
        manifest = RealModelStudyManifest.build(**values)
        benchmark = _load_artifact(
            benchmark_path,
            kind="process-equivalence-benchmark",
            model=ProcessEquivalenceBenchmarkManifest,
        )
        protocols = {
            condition_id: load_repeated_sensitivity_protocol(path)
            for condition_id, path in protocol_paths.items()
        }
        validate_study_manifest_inputs(manifest, benchmark, protocols)
        text = _safe_bounded_model_json(manifest, label="real-model study manifest")
        if RealModelStudyManifest.model_validate_json(text) != manifest:
            raise RuntimeError("finalized study manifest did not round-trip exactly")
        publish_finalize_outputs(((out, text, "real-model study manifest"),))
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"real-model study finalization failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("real-model study finalization failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"study id: {sanitize_display_text(manifest.study_id)}")
    typer.echo(f"manifest digest: {manifest.manifest_digest}")
    typer.echo(f"finalized study manifest: {display_path(out)}")


@app.command("bind-config")
def bind_config(
    manifest_path: Annotated[
        Path,
        typer.Option(
            "--manifest",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Final self-digested study manifest JSON.",
        ),
    ],
    benchmark_path: Annotated[
        Path,
        typer.Option(
            "--benchmark",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Digest-bound Process-Equivalence Benchmark JSON.",
        ),
    ],
    condition_id: Annotated[
        str,
        typer.Option("--condition-id", help="Frozen study condition identifier."),
    ],
    protocol_path: Annotated[
        Path,
        typer.Option(
            "--protocol",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Frozen repeated protocol for the selected condition.",
        ),
    ],
    compiled_suite_path: Annotated[
        Path,
        typer.Option(
            "--compiled-suite",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Compiled suite bound by the repeated protocol.",
        ),
    ],
    baseline_config_path: Annotated[
        Path,
        typer.Option(
            "--baseline-config",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Design-bound baseline live configuration.",
        ),
    ],
    counterfactual_config_path: Annotated[
        Path,
        typer.Option(
            "--counterfactual-config",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Design-bound counterfactual live configuration.",
        ),
    ],
    baseline_config_out: Annotated[
        Path,
        typer.Option(
            "--baseline-config-out",
            file_okay=True,
            dir_okay=False,
            help="Study-bound baseline config beside its input.",
        ),
    ],
    counterfactual_config_out: Annotated[
        Path,
        typer.Option(
            "--counterfactual-config-out",
            file_okay=True,
            dir_okay=False,
            help="Study-bound counterfactual config beside its input.",
        ),
    ],
) -> None:
    """Bind both exact live arms with lock-coordinated no-clobber publication."""

    try:
        ensure_finalize_paths(
            inputs=(
                manifest_path,
                benchmark_path,
                protocol_path,
                compiled_suite_path,
                baseline_config_path,
                counterfactual_config_path,
            ),
            outputs=(baseline_config_out, counterfactual_config_out),
            config_output_pairs=(
                (baseline_config_path, baseline_config_out),
                (counterfactual_config_path, counterfactual_config_out),
            ),
        )
        manifest = _load_artifact(
            manifest_path,
            kind="real-model-study-manifest",
            model=RealModelStudyManifest,
        )
        benchmark = _load_artifact(
            benchmark_path,
            kind="process-equivalence-benchmark",
            model=ProcessEquivalenceBenchmarkManifest,
        )
        protocol = load_repeated_sensitivity_protocol(protocol_path)
        compiled = load_compiled_suite(compiled_suite_path)
        baseline_config = load_live_run_config(baseline_config_path)
        counterfactual_config = load_live_run_config(counterfactual_config_path)
        reject_inline_environment_for_finalization(
            baseline_config,
            arm_name="baseline",
        )
        reject_inline_environment_for_finalization(
            counterfactual_config,
            arm_name="counterfactual",
        )
        bound_baseline = bind_study_manifest_to_live_config(
            manifest=manifest,
            benchmark=benchmark,
            condition_id=condition_id,
            protocol=protocol,
            arm_id="baseline_evidence",
            compiled=compiled,
            config=baseline_config,
            config_dir=baseline_config_path.parent,
        )
        bound_counterfactual = bind_study_manifest_to_live_config(
            manifest=manifest,
            benchmark=benchmark,
            condition_id=condition_id,
            protocol=protocol,
            arm_id="counterfactual_evidence",
            compiled=compiled,
            config=counterfactual_config,
            config_dir=counterfactual_config_path.parent,
        )
        baseline_text = bounded_model_json(
            bound_baseline,
            label="study-bound baseline live config",
        )
        counterfactual_text = bounded_model_json(
            bound_counterfactual,
            label="study-bound counterfactual live config",
        )
        if LiveRunConfig.model_validate_json(baseline_text) != bound_baseline:
            raise RuntimeError("study-bound baseline config did not round-trip exactly")
        if LiveRunConfig.model_validate_json(counterfactual_text) != bound_counterfactual:
            raise RuntimeError("study-bound counterfactual config did not round-trip exactly")
        publish_finalize_outputs(
            (
                (
                    baseline_config_out,
                    baseline_text,
                    "study-bound baseline live config",
                ),
                (
                    counterfactual_config_out,
                    counterfactual_text,
                    "study-bound counterfactual live config",
                ),
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"real-model study config binding failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("real-model study config binding failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"condition id: {sanitize_display_text(condition_id)}")
    typer.echo(f"manifest digest: {bound_baseline.study_manifest_digest}")
    typer.echo(f"study-bound baseline config: {display_path(baseline_config_out)}")
    typer.echo(f"study-bound counterfactual config: {display_path(counterfactual_config_out)}")


@app.command("analyze")
def analyze(
    manifest_path: Annotated[
        Path,
        typer.Option(
            "--manifest",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Final self-digested study manifest JSON.",
        ),
    ],
    benchmark_path: Annotated[
        Path,
        typer.Option(
            "--benchmark",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Exact benchmark JSON bound by the manifest.",
        ),
    ],
    evidence_path: Annotated[
        Path,
        typer.Option(
            "--evidence",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Relative-path study evidence descriptor in JSON or YAML.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=False,
            help="Atomic privacy-safe study publication directory.",
        ),
    ],
) -> None:
    """Recompute and publish a study from frozen privacy-filtered evidence."""

    try:
        input_budget = _StudyInputByteBudget()
        manifest = _load_artifact(
            manifest_path,
            kind="real-model-study-manifest",
            model=RealModelStudyManifest,
            byte_budget=input_budget,
        )
        benchmark = _load_artifact(
            benchmark_path,
            kind="process-equivalence-benchmark",
            model=ProcessEquivalenceBenchmarkManifest,
            byte_budget=input_budget,
        )
        descriptor = _StudyEvidenceDescriptor.model_validate(
            _load_authoring_mapping(
                evidence_path,
                label="study evidence descriptor",
                byte_budget=input_budget,
            )
        )
        manifest_condition_ids = tuple(item.condition_id for item in manifest.conditions)
        descriptor_condition_ids = tuple(item.condition_id for item in descriptor.conditions)
        if descriptor_condition_ids != manifest_condition_ids:
            raise ValueError(
                "study evidence descriptor must exactly cover the frozen condition IDs"
            )
        descriptor_root = evidence_path.parent
        registration_record_path = _resolve_descriptor_path(
            descriptor_root,
            descriptor.registration_record,
            directory=False,
            label="study registration record",
        )
        registration_review_path = _resolve_descriptor_path(
            descriptor_root,
            descriptor.registration_review_receipt,
            directory=False,
            label="study registration review receipt",
        )
        registration_record_bytes = read_bytes_bounded_from_filesystem_root(
            registration_record_path,
            max_bytes=input_budget.next_read_limit(MAX_ARTIFACT_JSON_BYTES),
            label="study registration record",
        )
        input_budget.consume_bytes(len(registration_record_bytes))
        registration_review_receipt = _load_artifact(
            registration_review_path,
            kind="real-model-study-registration-review",
            model=StudyRegistrationReviewReceipt,
            byte_budget=input_budget,
        )
        statistical_method_review_receipt = None
        statistical_method_review_path = None
        if descriptor.statistical_method_review_receipt is not None:
            statistical_method_review_path = _resolve_descriptor_path(
                descriptor_root,
                descriptor.statistical_method_review_receipt,
                directory=False,
                label="study statistical-method review receipt",
            )
            statistical_method_review_receipt = _load_artifact(
                statistical_method_review_path,
                kind="real-model-study-statistical-method-review",
                model=StudyStatisticalMethodReviewReceipt,
                byte_budget=input_budget,
            )
        execution_review_receipt = None
        execution_review_path = None
        if descriptor.execution_review_receipt is not None:
            execution_review_path = _resolve_descriptor_path(
                descriptor_root,
                descriptor.execution_review_receipt,
                directory=False,
                label="study execution review receipt",
            )
            execution_review_receipt = _load_artifact(
                execution_review_path,
                kind="real-model-study-execution-review",
                model=StudyExecutionReviewReceipt,
                byte_budget=input_budget,
            )
        protocols: dict[str, RepeatedEvidenceSensitivityProtocol] = {}
        evidence: dict[str, StudyConditionEvidence | None] = {}
        bindings = {item.condition_id: item for item in manifest.conditions}
        input_files: list[Path] = [
            manifest_path,
            benchmark_path,
            evidence_path,
            registration_record_path,
            registration_review_path,
        ]
        if execution_review_path is not None:
            input_files.append(execution_review_path)
        if statistical_method_review_path is not None:
            input_files.append(statistical_method_review_path)
        input_directories: list[Path] = []
        for condition in descriptor.conditions:
            registered_path = _resolve_descriptor_path(
                descriptor_root,
                condition.registered_protocol,
                directory=False,
                label="registered protocol",
            )
            registered, registered_size = load_repeated_sensitivity_protocol_with_size(
                registered_path,
                max_bytes=input_budget.next_read_limit(MAX_ARTIFACT_JSON_BYTES),
            )
            input_budget.consume_bytes(registered_size)
            protocols[condition.condition_id] = registered
            input_files.append(registered_path)
            if condition.source_run_directory is None:
                evidence[condition.condition_id] = None
                continue
            run_dir = _resolve_descriptor_path(
                descriptor_root,
                condition.source_run_directory,
                directory=True,
                label="source run directory",
            )
            source_protocol_path = run_dir / "repeated-evidence-sensitivity-protocol.json"
            baseline_path = run_dir / "baseline.runset.json"
            counterfactual_path = run_dir / "counterfactual.runset.json"
            for source_path in (source_protocol_path, baseline_path, counterfactual_path):
                if not source_path.is_file():
                    raise ValueError(
                        "source run directory is missing a required repeated-study artifact"
                    )
            source_protocol, source_protocol_size = load_repeated_sensitivity_protocol_with_size(
                source_protocol_path,
                max_bytes=input_budget.next_read_limit(MAX_ARTIFACT_JSON_BYTES),
            )
            input_budget.consume_bytes(source_protocol_size)
            baseline_runset, baseline_size = load_runset_with_size(
                baseline_path,
                max_bytes=input_budget.next_read_limit(MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES),
            )
            input_budget.consume_bytes(baseline_size)
            counterfactual_runset, counterfactual_size = load_runset_with_size(
                counterfactual_path,
                max_bytes=input_budget.next_read_limit(MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES),
            )
            input_budget.consume_bytes(counterfactual_size)
            observed_provenance = derive_study_observed_execution_provenance(
                manifest=manifest,
                binding=bindings[condition.condition_id],
                protocol=registered,
                baseline_runset=baseline_runset,
                counterfactual_runset=counterfactual_runset,
            )
            evidence[condition.condition_id] = StudyConditionEvidence(
                protocol=source_protocol,
                baseline_runset=baseline_runset,
                counterfactual_runset=counterfactual_runset,
                observed_execution_provenance=observed_provenance,
            )
            input_files.extend((source_protocol_path, baseline_path, counterfactual_path))
            input_directories.append(run_dir)

        ensure_output_does_not_alias_inputs(
            out=out,
            inputs=tuple(input_files),
            input_directories=tuple(input_directories),
        )
        report = analyze_real_model_study(
            manifest=manifest,
            benchmark=benchmark,
            protocols=protocols,
            evidence=evidence,
        )
        written = write_real_model_study_artifacts(
            manifest=manifest,
            benchmark=benchmark,
            protocols=protocols,
            evidence=evidence,
            report=report,
            registration_record_bytes=registration_record_bytes,
            registration_review_receipt=registration_review_receipt,
            statistical_method_review_receipt=statistical_method_review_receipt,
            execution_review_receipt=execution_review_receipt,
            out_dir=out,
        )
        verified_bundle = load_and_validate_study_bundle(out)
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        ValidationError,
        StudyOutputConflictError,
        StudyPrivacyError,
    ) as exc:
        typer.echo(f"real-model study analysis failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("real-model study analysis failed: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(
        "hypothesis classification: "
        f"{sanitize_display_text(report.hypothesis_classification.value)}"
    )
    typer.echo(f"protocol valid: {str(report.protocol_valid).lower()}")
    typer.echo(
        "statistical sufficiency satisfied: "
        f"{str(report.statistical_sufficiency_satisfied).lower()}"
    )
    typer.echo(f"study report: {display_path(written['real-model-study-report.json'])}")
    typer.echo(
        "closed study bundle publication ready: "
        f"{str(verified_bundle.is_publication_ready).lower()}"
    )
    if not verified_bundle.is_publication_ready:
        raise typer.Exit(1)


def _parse_condition_path_specs(
    values: list[str] | None,
    *,
    label: str,
) -> dict[str, Path]:
    if not values:
        raise ValueError(f"at least one --protocol {label} mapping is required")
    parsed: dict[str, Path] = {}
    for value in values:
        condition_id, separator, raw_path = value.partition("=")
        if not separator or not condition_id or not raw_path:
            raise ValueError(f"{label} mappings must use CONDITION_ID=PATH")
        if condition_id in parsed:
            raise ValueError(f"{label} condition IDs must be unique")
        path = Path(raw_path)
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"{label} path cannot be resolved") from exc
        if not resolved.is_file():
            raise ValueError(f"{label} path must identify a regular file")
        parsed[condition_id] = resolved
    return parsed


def _load_authoring_mapping(
    path: Path,
    *,
    label: str,
    byte_budget: _StudyInputByteBudget | None = None,
) -> dict[str, object]:
    max_bytes = (
        MAX_ARTIFACT_JSON_BYTES
        if byte_budget is None
        else byte_budget.next_read_limit(MAX_ARTIFACT_JSON_BYTES)
    )
    data = read_bytes_bounded_from_filesystem_root(
        path,
        max_bytes=max_bytes,
        label=label,
    )
    if byte_budget is not None:
        byte_budget.consume_bytes(len(data))
    text = data.decode("utf-8")
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


def _load_artifact(
    path: Path,
    *,
    kind: str,
    model: type[ArtifactModelT],
    byte_budget: _StudyInputByteBudget | None = None,
) -> ArtifactModelT:
    max_bytes = (
        MAX_ARTIFACT_JSON_BYTES
        if byte_budget is None
        else byte_budget.next_read_limit(MAX_ARTIFACT_JSON_BYTES)
    )
    payload, size = load_validated_artifact_payload_with_size(
        path,
        kind,
        max_bytes=max_bytes,
        label=f"{kind} JSON",
    )
    result = project_validated_artifact_payload(payload, model, kind=kind)
    if byte_budget is not None:
        byte_budget.consume_bytes(size)
    return result


def _resolve_descriptor_path(
    root: Path,
    relative: str,
    *,
    directory: bool,
    label: str,
) -> Path:
    parts = portable_relative_path_parts(relative)
    try:
        resolved_root = root.resolve(strict=True)
        resolved = resolved_root.joinpath(*parts).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} cannot be resolved") from exc
    if not resolved.is_relative_to(resolved_root):
        raise ValueError(f"{label} escapes the evidence descriptor root")
    if directory and not resolved.is_dir():
        raise ValueError(f"{label} must identify a directory")
    if not directory and not resolved.is_file():
        raise ValueError(f"{label} must identify a regular file")
    return resolved


def _safe_bounded_model_json(model: BaseModel, *, label: str) -> str:
    payload = model.model_dump(mode="json", warnings="error")
    assert_persisted_payload_safe(payload, owner=label)
    encoded = published_model_json_bytes(model)
    if len(encoded) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError(f"{label} exceeds the maximum supported size")
    return encoded.decode("utf-8")


__all__ = ["app"]
