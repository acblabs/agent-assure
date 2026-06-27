from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.release_evidence import (
    CORE_RELEASE_ROLES,
    load_digest_replay,
    verify_digest_replay,
)

app = typer.Typer(help="Release evidence utilities.")
console = Console()


@app.callback()
def callback() -> None:
    """Verify release evidence digests."""


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
            help="Require compiled suite, fixture manifest, packet, and manifest roles.",
        ),
    ] = True,
) -> None:
    try:
        replay_artifact = load_digest_replay(digest_replay)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    required_roles = tuple(require_role or ())
    if require_core:
        required_roles = (*CORE_RELEASE_ROLES, *required_roles)
    verification = verify_digest_replay(
        replay_artifact,
        artifact_root=artifact_root,
        required_roles=required_roles,
        expect_commit=expect_commit,
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
                    "expected_sha256": finding.expected_sha256,
                    "actual_sha256": finding.actual_sha256,
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
