from __future__ import annotations

from pathlib import Path

import pytest
import typer

from agent_assure.authoring.compiler import compile_suite
from agent_assure.cli.suite_cmd import _hmac_key_from_env, compile_cmd, lint, run_cmd
from agent_assure.fixtures.loader import write_compiled_suite
from agent_assure.io_limits import MAX_JSON_DEPTH

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")


def test_hmac_key_environment_value_rejects_short_utf8_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXTURE_KEY", "too-short")

    with pytest.raises(typer.BadParameter, match="at least 32 UTF-8 bytes"):
        _hmac_key_from_env("FIXTURE_KEY")


def test_hmac_key_environment_value_accepts_32_utf8_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FIXTURE_KEY", "x" * 32)

    assert _hmac_key_from_env("FIXTURE_KEY") == b"x" * 32


def test_suite_run_reports_over_depth_compiled_json_as_bad_parameter(tmp_path) -> None:  # type: ignore[no-untyped-def]
    compiled = tmp_path / "compiled.json"
    compiled.write_text("[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1))

    with pytest.raises(typer.BadParameter, match="exceeds maximum supported nesting depth"):
        run_cmd(
            compiled_suite=compiled,
            variant=tmp_path / "unused-variant.yaml",
            out=tmp_path / "runset.json",
            mode="fixture",
            suite_digest=None,
            source=None,
            suite_root=None,
            manifest=None,
            hmac_key_env=None,
        )


@pytest.mark.parametrize("command", (lint, compile_cmd))
def test_suite_yaml_commands_normalize_parser_errors(command, tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_text("suite_id: [\n", encoding="utf-8")

    with pytest.raises(typer.BadParameter, match="invalid YAML"):
        if command is lint:
            command(suite)
        else:
            command(suite, out=tmp_path / "compiled.json", manifest=None)


def test_suite_run_normalizes_unknown_runner_error(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:  # type: ignore[no-untyped-def]
    compiled_path = tmp_path / "compiled.json"
    variant_path = tmp_path / "variant.yaml"
    write_compiled_suite(compile_suite(SUITE), compiled_path)
    variant_path.write_text(
        "variant_id: unknown-runner\npipeline_id: test\nrunner_id: unknown.runner\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FIXTURE_KEY", "x" * 32)

    with pytest.raises(typer.BadParameter, match="unknown runner_id"):
        run_cmd(
            compiled_suite=compiled_path,
            variant=variant_path,
            out=tmp_path / "runset.json",
            mode="fixture",
            suite_digest=None,
            source=SUITE,
            suite_root=SUITE.parent,
            manifest=None,
            hmac_key_env="FIXTURE_KEY",
        )
