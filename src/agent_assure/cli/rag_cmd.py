from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.cli import study_cmd
from agent_assure.cli._publication import (
    bounded_model_json as _bounded_model_json,
)
from agent_assure.cli._publication import (
    ensure_finalize_paths as _ensure_repeated_finalize_paths,
)
from agent_assure.cli._publication import (
    ensure_output_does_not_alias_inputs as _ensure_repeated_output_does_not_alias_inputs,
)
from agent_assure.cli._publication import (
    is_within as _is_within,
)
from agent_assure.cli._publication import (
    publish_finalize_outputs as _publish_finalize_outputs,
)
from agent_assure.cli._publication import (
    reject_inline_environment_for_finalization as _reject_inline_environment_for_finalization,
)
from agent_assure.cli._publication import (
    same_file as _same_file,
)
from agent_assure.cli.live_cmd import _confirm_trusted_live_config
from agent_assure.evaluation.evaluator import load_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.fixtures.resolver import FixtureResolver
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
    loads_json_bounded,
    read_text_bounded_from_filesystem_root,
)
from agent_assure.live.config import LiveRunConfig, load_live_run_config
from agent_assure.onboarding.diagnostics import bounded_error, display_path
from agent_assure.rag.repeated_sensitivity import (
    assemble_paired_observations,
    build_paired_runset_dependencies,
    calculate_live_arm_binding_facts,
    execution_attempt_journal_path,
    load_repeated_sensitivity_protocol,
    run_repeated_live_study,
)
from agent_assure.rag.sensitivity import (
    SensitivityInputError,
    execute_sensitivity_experiment,
    write_sensitivity_artifacts,
)
from agent_assure.rag.sensitivity_statistics import (
    build_stochastic_sensitivity_report,
    evaluate_statistical_sufficiency,
    validate_binary_paired_design_plan,
)
from agent_assure.reporting.sensitivity import (
    SENSITIVITY_OUTPUT_FILENAMES,
    SensitivityOutputConflictError,
    SensitivityPrivacyError,
    ensure_sensitivity_output_namespace,
)
from agent_assure.reporting.stochastic_sensitivity import (
    RepeatedSensitivityOutputConflictError,
    RepeatedSensitivityPrivacyError,
    write_repeated_analysis_artifacts,
    write_repeated_run_artifacts,
)
from agent_assure.reporting.text_safety import sanitize_display_text
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.sensitivity import EvidenceSensitivityExpectedRelation
from agent_assure.schema.stochastic_sensitivity import (
    RepeatedEvidenceSensitivityProtocol,
    SensitivityExecutionMode,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
)
from agent_assure.sensitivity_contract import SENSITIVITY_HARNESS_NOTICE

app = typer.Typer(help="Deterministic retrieval-augmented-generation assurance.")
sensitivity_app = typer.Typer(
    help="Deterministic or repeated paired evidence-sensitivity workflows.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(sensitivity_app, name="sensitivity")
app.add_typer(study_cmd.app, name="study")

_OWNED_OUTPUT_FILENAMES = SENSITIVITY_OUTPUT_FILENAMES


@app.callback()
def callback() -> None:
    """Run deterministic RAG assurance workflows."""


@sensitivity_app.callback(invoke_without_command=True)
def sensitivity(
    ctx: typer.Context,
    suite: Annotated[
        Path | None,
        typer.Option(
            "--suite",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="One-case deterministic sensitivity suite YAML.",
        ),
    ] = None,
    baseline_corpus: Annotated[
        Path | None,
        typer.Option(
            "--baseline-corpus",
            exists=True,
            file_okay=False,
            readable=True,
            help="Digest-addressed baseline corpus directory.",
        ),
    ] = None,
    counterfactual_corpus: Annotated[
        Path | None,
        typer.Option(
            "--counterfactual-corpus",
            exists=True,
            file_okay=False,
            readable=True,
            help="Digest-addressed counterfactual corpus directory.",
        ),
    ] = None,
    knowledge_contract: Annotated[
        Path | None,
        typer.Option(
            "--knowledge-contract",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Self-digested knowledge-authority contract YAML.",
        ),
    ] = None,
    expected_relation: Annotated[
        EvidenceSensitivityExpectedRelation | None,
        typer.Option(
            "--expected-relation",
            case_sensitive=True,
            help="Predeclared expected decision relation.",
        ),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            file_okay=False,
            help="Controlled evidence-sensitivity artifact directory.",
        ),
    ] = None,
    synthetic_data_attestation: Annotated[
        Path | None,
        typer.Option(
            "--synthetic-data-attestation",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help=(
                "Self-digested exact-input attestation required for custom corpora; "
                "bundled digest-verified inputs must omit it."
            ),
        ),
    ] = None,
) -> None:
    """Rerun a deterministic subject or select a repeated paired subcommand."""
    if ctx.invoked_subcommand is not None:
        return
    missing = tuple(
        option
        for option, value in (
            ("--suite", suite),
            ("--baseline-corpus", baseline_corpus),
            ("--counterfactual-corpus", counterfactual_corpus),
            ("--knowledge-contract", knowledge_contract),
            ("--expected-relation", expected_relation),
            ("--out", out),
        )
        if value is None
    )
    if missing:
        raise typer.BadParameter(
            "deterministic sensitivity requires options: " + ", ".join(missing)
        )
    assert suite is not None
    assert baseline_corpus is not None
    assert counterfactual_corpus is not None
    assert knowledge_contract is not None
    assert expected_relation is not None
    assert out is not None
    try:
        _ensure_output_does_not_alias_inputs(
            out=out,
            suite=suite,
            knowledge_contract=knowledge_contract,
            synthetic_data_attestation=synthetic_data_attestation,
            corpus_dirs=(baseline_corpus, counterfactual_corpus),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        typer.echo(f"invalid evidence-sensitivity input: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("evidence-sensitivity execution error: bounded internal error")
        raise typer.Exit(4) from exc

    try:
        artifacts = execute_sensitivity_experiment(
            suite_path=suite,
            baseline_corpus_dir=baseline_corpus,
            counterfactual_corpus_dir=counterfactual_corpus,
            knowledge_contract_path=knowledge_contract,
            expected_relation=expected_relation,
            synthetic_data_attestation_path=synthetic_data_attestation,
        )
    except SensitivityInputError as exc:
        typer.echo(f"invalid evidence-sensitivity input: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"evidence-sensitivity execution error: {bounded_error(exc)}")
        raise typer.Exit(4) from exc
    except Exception as exc:
        typer.echo("evidence-sensitivity execution error: bounded internal error")
        raise typer.Exit(4) from exc

    try:
        _ensure_output_does_not_overlap_fixture_roots(
            out=out,
            suite=suite,
            compiled_suite=artifacts.compiled_suite,
        )
        ensure_sensitivity_output_namespace(out)
    except (OSError, RuntimeError, ValueError) as exc:
        typer.echo(f"invalid evidence-sensitivity input: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("evidence-sensitivity execution error: bounded internal error")
        raise typer.Exit(4) from exc

    try:
        written = write_sensitivity_artifacts(artifacts, out)
    except (SensitivityOutputConflictError, SensitivityPrivacyError) as exc:
        typer.echo(f"invalid evidence-sensitivity input: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"evidence-sensitivity execution error: {bounded_error(exc)}")
        raise typer.Exit(4) from exc
    except Exception as exc:
        typer.echo("evidence-sensitivity execution error: bounded internal error")
        raise typer.Exit(4) from exc

    report = artifacts.report
    typer.echo(f"scope notice: {sanitize_display_text(SENSITIVITY_HARNESS_NOTICE)}")
    typer.echo(
        f"controlled evidence sensitivity state: {sanitize_display_text(report.state.value)}"
    )
    typer.echo(f"gate effect: {sanitize_display_text(report.gate_effect.value)}")
    typer.echo(
        f"outcome classification: {sanitize_display_text(report.outcome_classification.value)}"
    )
    typer.echo(f"outcome: {sanitize_display_text(report.outcome_message)}")
    typer.echo(f"expected relation: {sanitize_display_text(report.expected_relation.value)}")
    typer.echo(f"observed relation: {sanitize_display_text(report.observed_relation.value)}")
    typer.echo(
        "synthetic data provenance: "
        f"{sanitize_display_text(report.synthetic_data_provenance.value)}"
    )
    typer.echo(f"raw content persistence: {sanitize_display_text(report.raw_content_persistence)}")
    typer.echo(
        f"decision inertia detected: {str(report.decision_inertia_finding.detected).lower()}"
    )
    typer.echo(f"evidence sensitivity report: {display_path(written['evidence-sensitivity.json'])}")
    typer.echo(f"canonical comparison summary: {display_path(written['comparison-summary.json'])}")
    typer.echo(
        f"assurance evidence graph: {display_path(written['assurance-evidence-graph.json'])}"
    )
    typer.echo(
        f"release artifact manifest: {display_path(written['release-artifact-manifest.json'])}"
    )
    typer.echo(f"evidence packet: {display_path(written['evidence-packet.json'])}")
    typer.echo(f"evidence packet markdown: {display_path(written['evidence-packet.md'])}")
    typer.echo(f"evidence sensitivity markdown: {display_path(written['evidence-sensitivity.md'])}")
    typer.echo(f"evidence sensitivity HTML: {display_path(written['evidence-sensitivity.html'])}")
    if report.exit_code:
        raise typer.Exit(report.exit_code)


@sensitivity_app.command("plan")
def repeated_sensitivity_plan(
    protocol_path: Annotated[
        Path,
        typer.Option(
            "--protocol",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Self-digested repeated evidence-sensitivity protocol JSON or YAML.",
        ),
    ],
) -> None:
    """Validate and independently recompute the predeclared binary power plan."""
    try:
        protocol = load_repeated_sensitivity_protocol(protocol_path)
        design = validate_binary_paired_design_plan(protocol)
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"invalid repeated sensitivity protocol: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    payload = {
        "protocol_id": protocol.protocol_id,
        "protocol_digest": protocol.protocol_digest,
        "endpoint": protocol.endpoint,
        "interpretation": protocol.interpretation.value,
        "execution_mode": protocol.execution_mode.value,
        "planned_pairs": protocol.planned_pairs,
        "planned_clusters": len(protocol.planned_cluster_ids),
        "design": design.model_dump(mode="json"),
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@sensitivity_app.command("finalize")
def repeated_sensitivity_finalize(
    template_path: Annotated[
        Path,
        typer.Option(
            "--template",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Repeated sensitivity authoring payload in JSON or YAML.",
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
            help="Compiled suite whose exact cases are bound by both live arms.",
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
            help="Uncommitted baseline live configuration.",
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
            help="Uncommitted counterfactual live configuration.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=True,
            dir_okay=False,
            help="Self-digested repeated sensitivity protocol JSON.",
        ),
    ],
    baseline_config_out: Annotated[
        Path,
        typer.Option(
            "--baseline-config-out",
            file_okay=True,
            dir_okay=False,
            help=(
                "Final baseline config JSON; must remain beside its input so "
                "relative resource bindings retain their meaning."
            ),
        ),
    ],
    counterfactual_config_out: Annotated[
        Path,
        typer.Option(
            "--counterfactual-config-out",
            file_okay=True,
            dir_okay=False,
            help=(
                "Final counterfactual config JSON; must remain beside its input "
                "so relative resource bindings retain their meaning."
            ),
        ),
    ],
) -> None:
    """Content-bind live arms and finalize a no-dispatch repeated-study protocol."""
    try:
        _ensure_repeated_finalize_paths(
            inputs=(
                template_path,
                compiled_suite_path,
                baseline_config_path,
                counterfactual_config_path,
            ),
            outputs=(out, baseline_config_out, counterfactual_config_out),
            config_output_pairs=(
                (baseline_config_path, baseline_config_out),
                (counterfactual_config_path, counterfactual_config_out),
            ),
        )
        text = read_text_bounded_from_filesystem_root(
            template_path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="repeated sensitivity authoring payload",
        )
        if template_path.suffix.lower() == ".json":
            payload = loads_json_bounded(
                text,
                label="repeated sensitivity authoring payload",
            )
        elif template_path.suffix.lower() in {".yaml", ".yml"}:
            payload = safe_load_yaml_text(
                text,
                label="repeated sensitivity authoring payload",
            )
        else:
            raise ValueError("authoring payload must use .json, .yaml, or .yml")
        if not isinstance(payload, dict):
            raise TypeError("repeated sensitivity authoring payload must be a mapping")
        values = dict(payload)
        values.pop("protocol_digest", None)
        values.pop("design_commitment_digest", None)
        compiled = load_compiled_suite(compiled_suite_path)
        baseline_config = load_live_run_config(baseline_config_path)
        counterfactual_config = load_live_run_config(counterfactual_config_path)
        _reject_inline_environment_for_finalization(
            baseline_config,
            arm_name="baseline",
        )
        _reject_inline_environment_for_finalization(
            counterfactual_config,
            arm_name="counterfactual",
        )
        if (
            baseline_config.evidence_sensitivity_design_digest is not None
            or counterfactual_config.evidence_sensitivity_design_digest is not None
        ):
            raise ValueError(
                "finalize requires uncommitted configs without evidence_sensitivity_design_digest"
            )
        baseline_facts = calculate_live_arm_binding_facts(
            compiled=compiled,
            config=baseline_config,
            config_dir=baseline_config_path.parent,
        )
        counterfactual_facts = calculate_live_arm_binding_facts(
            compiled=compiled,
            config=counterfactual_config,
            config_dir=counterfactual_config_path.parent,
        )
        baseline_authority = baseline_facts.get("case_authority_bindings")
        counterfactual_authority = counterfactual_facts.get("case_authority_bindings")
        if (
            not isinstance(baseline_authority, tuple)
            or baseline_authority != counterfactual_authority
        ):
            raise ValueError("live arms do not derive the same exact per-case authority projection")
        values["case_authority_bindings"] = baseline_authority
        values["baseline_arm"] = _finalized_arm_payload(
            values.get("baseline_arm"),
            arm_id="baseline_evidence",
            facts=baseline_facts,
        )
        values["counterfactual_arm"] = _finalized_arm_payload(
            values.get("counterfactual_arm"),
            arm_id="counterfactual_evidence",
            facts=counterfactual_facts,
        )
        protocol = RepeatedEvidenceSensitivityProtocol.build(**values)
        finalized_baseline = _bind_design_to_live_config(baseline_config, protocol)
        finalized_counterfactual = _bind_design_to_live_config(
            counterfactual_config,
            protocol,
        )
        for arm_name, finalized_config, config_path, expected_facts in (
            (
                "baseline",
                finalized_baseline,
                baseline_config_path,
                baseline_facts,
            ),
            (
                "counterfactual",
                finalized_counterfactual,
                counterfactual_config_path,
                counterfactual_facts,
            ),
        ):
            observed = calculate_live_arm_binding_facts(
                compiled=compiled,
                config=finalized_config,
                config_dir=config_path.parent,
            )
            if observed != expected_facts:
                raise RuntimeError(
                    f"{arm_name} arm identity changed after design commitment injection"
                )
        baseline_text = _bounded_model_json(
            finalized_baseline,
            label="finalized baseline live config",
        )
        counterfactual_text = _bounded_model_json(
            finalized_counterfactual,
            label="finalized counterfactual live config",
        )
        protocol_text = _bounded_model_json(
            protocol,
            label="finalized repeated sensitivity protocol",
        )
        if LiveRunConfig.model_validate_json(baseline_text) != finalized_baseline:
            raise RuntimeError("finalized baseline live config did not round-trip exactly")
        if LiveRunConfig.model_validate_json(counterfactual_text) != finalized_counterfactual:
            raise RuntimeError("finalized counterfactual live config did not round-trip exactly")
        if RepeatedEvidenceSensitivityProtocol.model_validate_json(protocol_text) != protocol:
            raise RuntimeError("finalized protocol did not round-trip exactly")
        _publish_finalize_outputs(
            (
                (
                    baseline_config_out,
                    baseline_text,
                    "finalized baseline live config",
                ),
                (
                    counterfactual_config_out,
                    counterfactual_text,
                    "finalized counterfactual live config",
                ),
                (
                    out,
                    protocol_text,
                    "finalized repeated sensitivity protocol",
                ),
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"repeated sensitivity finalization failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    typer.echo(f"protocol id: {sanitize_display_text(protocol.protocol_id)}")
    typer.echo(f"protocol digest: {protocol.protocol_digest}")
    typer.echo(f"design commitment digest: {protocol.design_commitment_digest}")
    typer.echo(f"baseline finalized config: {display_path(baseline_config_out)}")
    typer.echo(f"counterfactual finalized config: {display_path(counterfactual_config_out)}")
    typer.echo(f"finalized protocol: {display_path(out)}")


@sensitivity_app.command("analyze")
def repeated_sensitivity_analyze(
    protocol_path: Annotated[
        Path,
        typer.Option(
            "--protocol",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Self-digested repeated evidence-sensitivity protocol JSON or YAML.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=False,
            help="Atomic statistical analysis artifact directory.",
        ),
    ],
    runset_dir: Annotated[
        Path | None,
        typer.Option(
            "--runset",
            exists=True,
            file_okay=False,
            readable=True,
            help=(
                "Paired run directory containing baseline.runset.json and "
                "counterfactual.runset.json."
            ),
        ),
    ] = None,
    baseline_runset: Annotated[
        Path | None,
        typer.Option(
            "--baseline-runset",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Baseline arm RunSet JSON when --runset is not used.",
        ),
    ] = None,
    counterfactual_runset: Annotated[
        Path | None,
        typer.Option(
            "--counterfactual-runset",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Counterfactual arm RunSet JSON when --runset is not used.",
        ),
    ] = None,
) -> None:
    """Outer-join paired observations and emit sufficiency-bound evidence."""
    try:
        if runset_dir is not None:
            if baseline_runset is not None or counterfactual_runset is not None:
                raise ValueError("--runset cannot be combined with explicit arm RunSet options")
            baseline_path = runset_dir / "baseline.runset.json"
            counterfactual_path = runset_dir / "counterfactual.runset.json"
        else:
            if baseline_runset is None or counterfactual_runset is None:
                raise ValueError(
                    "supply --runset or both --baseline-runset and --counterfactual-runset"
                )
            baseline_path = baseline_runset
            counterfactual_path = counterfactual_runset
        if not baseline_path.is_file() or not counterfactual_path.is_file():
            raise ValueError("paired run directory is missing an arm RunSet")
        _ensure_repeated_output_does_not_alias_inputs(
            out=out,
            inputs=(protocol_path, baseline_path, counterfactual_path),
            input_directories=((runset_dir,) if runset_dir is not None else ()),
        )
        protocol = load_repeated_sensitivity_protocol(protocol_path)
        baseline = load_runset(
            baseline_path,
            max_bytes=MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
        )
        counterfactual = load_runset(
            counterfactual_path,
            max_bytes=MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
        )
        observations = assemble_paired_observations(
            protocol,
            baseline,
            counterfactual,
        )
        source_runsets = (
            ()
            if protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
            else build_paired_runset_dependencies(
                protocol,
                baseline,
                counterfactual,
            )
        )
        sufficiency = evaluate_statistical_sufficiency(
            protocol,
            observations,
            source_runsets=source_runsets,
        )
        report = build_stochastic_sensitivity_report(sufficiency)
        written = write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out,
        )
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        ValidationError,
        RepeatedSensitivityOutputConflictError,
        RepeatedSensitivityPrivacyError,
    ) as exc:
        typer.echo(f"repeated sensitivity analysis failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    typer.echo(f"stochastic sensitivity state: {report.state.value}")
    typer.echo(f"sufficiency state: {sufficiency.state.value}")
    typer.echo(f"observed counterexamples: {report.observed_counterexample_count}")
    typer.echo(
        "estimated independent-cluster response rate: "
        f"{report.estimated_response_rate or 'not estimated'}"
    )
    typer.echo(
        "statistical sufficiency report: "
        f"{display_path(written['statistical-sufficiency-report.json'])}"
    )
    typer.echo(
        "stochastic sensitivity report: "
        f"{display_path(written['stochastic-evidence-sensitivity.json'])}"
    )
    if report.state.value != "pass":
        raise typer.Exit(1)


@sensitivity_app.command("run")
def repeated_sensitivity_run(
    protocol_path: Annotated[
        Path,
        typer.Option(
            "--protocol",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Pre-bound repeated evidence-sensitivity protocol JSON or YAML.",
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
            help="Compiled suite JSON used by both live arms.",
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
            help="Exact baseline live configuration.",
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
            help="Exact counterfactual live configuration.",
        ),
    ],
    live_protocol_path: Annotated[
        Path,
        typer.Option(
            "--live-protocol",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Existing operational live budget, stopping, and safety protocol.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=False,
            help="New atomic paired RunSet artifact directory.",
        ),
    ],
    network_opt_in: Annotated[
        bool,
        typer.Option(
            "--network-opt-in",
            help="Explicitly authorize configured provider network egress.",
        ),
    ] = False,
    trust_config: Annotated[
        bool,
        typer.Option(
            "--trust-config",
            help="Acknowledge trusted live configuration execution.",
        ),
    ] = False,
    ci: Annotated[
        bool,
        typer.Option(
            "--ci",
            help="Non-interactive mode; requires --trust-config for risky adapters.",
        ),
    ] = False,
    allow_external_script: Annotated[
        bool,
        typer.Option(
            "--allow-external-script",
            help="Authorize a configured external-script adapter.",
        ),
    ] = False,
    allow_script_env: Annotated[
        bool,
        typer.Option(
            "--allow-script-env",
            help="Authorize allowlisted host environment values for an external script.",
        ),
    ] = False,
) -> None:
    """Execute exact pre-bound arms through the existing live adapters."""
    try:
        _ensure_repeated_output_does_not_alias_inputs(
            out=out,
            inputs=(
                protocol_path,
                compiled_suite_path,
                baseline_config_path,
                counterfactual_config_path,
                live_protocol_path,
            ),
        )
        if out.exists():
            raise ValueError(
                "paired live output directory must not exist before provider execution"
            )
        protocol = load_repeated_sensitivity_protocol(protocol_path)
        compiled = load_compiled_suite(compiled_suite_path)
        baseline_config = load_live_run_config(baseline_config_path)
        counterfactual_config = load_live_run_config(counterfactual_config_path)
        live_protocol = _load_operational_live_protocol(live_protocol_path)
        if not network_opt_in:
            raise ValueError("paired live execution requires explicit --network-opt-in")
        baseline_trust = _confirm_trusted_live_config(
            baseline_config,
            trust_config=trust_config,
            ci=ci,
            allow_network=network_opt_in,
            allow_external_script=allow_external_script,
            allow_script_env=allow_script_env,
        )
        counterfactual_trust = _confirm_trusted_live_config(
            counterfactual_config,
            trust_config=trust_config,
            ci=ci,
            allow_network=network_opt_in,
            allow_external_script=allow_external_script,
            allow_script_env=allow_script_env,
        )
        registered_protocol_path = protocol_path.resolve(strict=True)
        attempt_journal = execution_attempt_journal_path(registered_protocol_path, protocol)
        baseline, counterfactual = run_repeated_live_study(
            compiled=compiled,
            protocol=protocol,
            baseline_config=baseline_config,
            counterfactual_config=counterfactual_config,
            operational_protocol=live_protocol,
            baseline_config_dir=baseline_config_path.parent,
            counterfactual_config_dir=counterfactual_config_path.parent,
            baseline_trust=baseline_trust,
            counterfactual_trust=counterfactual_trust,
            registered_protocol_path=registered_protocol_path,
        )
        written = write_repeated_run_artifacts(
            protocol=protocol,
            baseline=baseline,
            counterfactual=counterfactual,
            out_dir=out,
        )
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        ValidationError,
        RepeatedSensitivityOutputConflictError,
        RepeatedSensitivityPrivacyError,
    ) as exc:
        typer.echo(f"repeated sensitivity execution failed: {bounded_error(exc)}")
        raise typer.Exit(2) from exc
    typer.echo(f"baseline RunSet: {display_path(written['baseline.runset.json'])}")
    typer.echo(f"counterfactual RunSet: {display_path(written['counterfactual.runset.json'])}")
    typer.echo("execution attempt journal: " + display_path(attempt_journal))


def _load_operational_live_protocol(path: Path) -> LiveProtocolRecord:
    payload = load_validated_artifact_payload(
        path,
        "live-protocol-record",
        label="live protocol JSON",
    )
    return project_validated_artifact_payload(
        payload,
        LiveProtocolRecord,
        kind="live-protocol-record",
    )


def _ensure_output_does_not_alias_inputs(
    *,
    out: Path,
    suite: Path,
    knowledge_contract: Path,
    synthetic_data_attestation: Path | None,
    corpus_dirs: tuple[Path, Path],
) -> None:
    try:
        resolved_out = out.resolve(strict=False)
        resolved_files = tuple(
            path.resolve(strict=True)
            for path in (suite, knowledge_contract, synthetic_data_attestation)
            if path is not None
        )
        resolved_corpora = tuple(path.resolve(strict=True) for path in corpus_dirs)
    except (OSError, RuntimeError) as exc:
        raise ValueError("sensitivity input or output path cannot be safely resolved") from exc
    if resolved_out == Path(resolved_out.anchor):
        raise ValueError("sensitivity output directory must not be a filesystem root")
    ensure_sensitivity_output_namespace(resolved_out)
    if any(
        _is_within(resolved_out, corpus) or _is_within(corpus, resolved_out)
        for corpus in resolved_corpora
    ):
        raise ValueError("sensitivity output directory must not overlap an input corpus")
    destinations = tuple(resolved_out / name for name in _OWNED_OUTPUT_FILENAMES)
    if any(
        source == destination or _same_file(source, destination)
        for source in resolved_files
        for destination in destinations
    ):
        raise ValueError("sensitivity input aliases an owned output artifact")


def _ensure_output_does_not_overlap_fixture_roots(
    *,
    out: Path,
    suite: Path,
    compiled_suite: CompiledSuite,
) -> None:
    resolved_out = out.resolve(strict=False)
    resolver = FixtureResolver(suite.resolve(strict=True).parent)
    fixture_roots = tuple(
        resolver.resolve(relative_root) for relative_root in compiled_suite.defaults.fixture_roots
    )
    if any(
        _is_within(resolved_out, fixture_root) or _is_within(fixture_root, resolved_out)
        for fixture_root in fixture_roots
    ):
        raise ValueError("sensitivity output directory must not overlap a fixture root")


def _finalized_arm_payload(
    authored: object,
    *,
    arm_id: str,
    facts: dict[str, object],
) -> dict[str, object]:
    if not isinstance(authored, dict):
        raise TypeError(f"{arm_id} authoring arm must be a mapping")
    declared_arm_id = authored.get("arm_id")
    if declared_arm_id != arm_id:
        raise ValueError(f"{arm_id} authoring arm has the wrong arm_id")
    arm_facts = {
        field_name: value
        for field_name, value in facts.items()
        if field_name != "case_authority_bindings"
    }
    return {**authored, **arm_facts, "arm_id": arm_id}


def _bind_design_to_live_config(
    config: LiveRunConfig,
    protocol: RepeatedEvidenceSensitivityProtocol,
) -> LiveRunConfig:
    payload = config.model_dump(mode="python")
    payload["evidence_sensitivity_design_digest"] = protocol.design_commitment_digest
    return LiveRunConfig.model_validate(payload)


__all__ = ["app", "sensitivity"]
