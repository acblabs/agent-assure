from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.authoring.compiler import compile_suite
from agent_assure.authoring.yaml_lint import lint_yaml
from agent_assure.fixtures.loader import load_compiled_suite, write_compiled_suite
from agent_assure.fixtures.manifest import (
    build_fixture_manifest,
    load_fixture_manifest,
    write_fixture_manifest,
)
from agent_assure.runner.fixture_runner import load_variant_config, run_suite, write_runset
from agent_assure.schema.common import ExecutionMode, coerce_enum

app = typer.Typer(help="Suite authoring and compilation.")
console = Console()


@app.command("lint")
def lint(path: Annotated[Path, typer.Argument(exists=True, readable=True)]) -> None:
    warnings = lint_yaml(path)
    for warning in warnings:
        console.print(f"{warning.path}:{warning.line}:{warning.column}: warning: {warning.message}")
    try:
        compile_suite(path)
    except Exception as exc:
        raise typer.BadParameter(f"suite lint failed: {exc}") from exc
    console.print(f"lint ok: {path} ({len(warnings)} warning(s))")


@app.command("compile")
def compile_cmd(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out", help="Compiled JSON output path.")],
    manifest: Annotated[
        Path | None,
        typer.Option("--manifest", help="Fixture manifest JSON output path."),
    ] = None,
) -> None:
    compiled = compile_suite(path)
    if compiled.defaults.execution_mode is ExecutionMode.live:
        raise typer.BadParameter(
            "live execution mode is handled by the agent-assure live command namespace"
        )
    write_compiled_suite(compiled, out)
    console.print(f"compiled suite: {out}")
    if manifest is not None:
        fixture_manifest = build_fixture_manifest(compiled, path.parent)
        write_fixture_manifest(fixture_manifest, manifest)
        console.print(f"fixture manifest: {manifest}")


@app.command("run")
def run_cmd(
    compiled_suite: Annotated[Path, typer.Argument(exists=True, readable=True)],
    variant: Annotated[Path, typer.Option("--variant", exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out", help="RunSet JSON output path.")],
    mode: Annotated[str, typer.Option("--mode", help="Execution mode.")] = "fixture",
    suite_digest: Annotated[
        str | None,
        typer.Option("--suite-digest", help="Expected compiled-suite digest."),
    ] = None,
    source: Annotated[
        Path | None,
        typer.Option("--source", exists=True, readable=True, help="Source suite YAML."),
    ] = None,
    suite_root: Annotated[
        Path | None,
        typer.Option("--suite-root", exists=True, file_okay=False, dir_okay=True),
    ] = None,
    manifest: Annotated[
        Path | None,
        typer.Option("--manifest", exists=True, readable=True, help="Expected fixture manifest."),
    ] = None,
) -> None:
    execution_mode = coerce_enum(ExecutionMode, mode)
    if execution_mode is ExecutionMode.live:
        raise typer.BadParameter(
            "live execution mode is handled by the agent-assure live command namespace"
        )
    compiled = load_compiled_suite(compiled_suite, expected_digest=suite_digest)
    variant_config = load_variant_config(variant)
    root = suite_root or _infer_suite_root(compiled_suite, variant)
    source_yaml = source or _default_source_yaml(root)
    expected_manifest = load_fixture_manifest(manifest) if manifest is not None else None
    runset = run_suite(
        compiled,
        variant_config,
        root,
        mode=execution_mode,
        expected_manifest=expected_manifest,
        source_yaml=source_yaml,
    )
    write_runset(runset, out)
    console.print(f"run set: {out}")


def _infer_suite_root(compiled_suite: Path, variant: Path) -> Path:
    if variant.parent.name == "variants":
        return variant.parent.parent
    return compiled_suite.parent


def _default_source_yaml(suite_root: Path) -> Path | None:
    candidate = suite_root / "suite.yaml"
    if candidate.exists():
        return candidate
    return None
