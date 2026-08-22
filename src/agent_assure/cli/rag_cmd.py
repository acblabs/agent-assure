from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from agent_assure.fixtures.resolver import FixtureResolver
from agent_assure.onboarding.diagnostics import bounded_error, display_path
from agent_assure.rag.sensitivity import (
    SensitivityInputError,
    execute_sensitivity_experiment,
    write_sensitivity_artifacts,
)
from agent_assure.reporting.sensitivity import (
    SENSITIVITY_OUTPUT_FILENAMES,
    SensitivityOutputConflictError,
    SensitivityPrivacyError,
    ensure_sensitivity_output_namespace,
)
from agent_assure.reporting.text_safety import sanitize_display_text
from agent_assure.schema.sensitivity import EvidenceSensitivityExpectedRelation
from agent_assure.schema.suite import CompiledSuite
from agent_assure.sensitivity_contract import SENSITIVITY_HARNESS_NOTICE

app = typer.Typer(help="Deterministic retrieval-augmented-generation assurance.")

_OWNED_OUTPUT_FILENAMES = SENSITIVITY_OUTPUT_FILENAMES


@app.callback()
def callback() -> None:
    """Run deterministic RAG assurance workflows."""


@app.command("sensitivity")
def sensitivity(
    suite: Annotated[
        Path,
        typer.Option(
            "--suite",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="One-case deterministic sensitivity suite YAML.",
        ),
    ],
    baseline_corpus: Annotated[
        Path,
        typer.Option(
            "--baseline-corpus",
            exists=True,
            file_okay=False,
            readable=True,
            help="Digest-addressed baseline corpus directory.",
        ),
    ],
    counterfactual_corpus: Annotated[
        Path,
        typer.Option(
            "--counterfactual-corpus",
            exists=True,
            file_okay=False,
            readable=True,
            help="Digest-addressed counterfactual corpus directory.",
        ),
    ],
    knowledge_contract: Annotated[
        Path,
        typer.Option(
            "--knowledge-contract",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Self-digested knowledge-authority contract YAML.",
        ),
    ],
    expected_relation: Annotated[
        EvidenceSensitivityExpectedRelation,
        typer.Option(
            "--expected-relation",
            case_sensitive=True,
            help="Predeclared expected decision relation.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            file_okay=False,
            help="Controlled evidence-sensitivity artifact directory.",
        ),
    ],
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
    """Rerun a deterministic subject against two authoritative corpora."""
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


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        return False


__all__ = ["app", "sensitivity"]
