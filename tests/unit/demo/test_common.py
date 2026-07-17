from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_assure.demo.common import (
    DEMO_MARKER_FILENAME,
    MAX_DEMO_MARKER_BYTES,
    DemoError,
    ExpectedCommandResult,
    demo_subprocess_env,
    prepare_output_dir,
    run_cli_command,
)


def test_prepare_output_dir_refuses_to_clean_non_empty_unowned_directory(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    keep = existing / "keep.txt"
    keep.write_text("do not delete\n", encoding="utf-8")

    with pytest.raises(DemoError, match="without agent-assure demo ownership marker"):
        prepare_output_dir(existing, clean=True)

    assert keep.read_text(encoding="utf-8") == "do not delete\n"


def test_prepare_output_dir_refuses_no_clean_non_empty_unowned_directory(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    keep = existing / "keep.txt"
    keep.write_text("do not overwrite\n", encoding="utf-8")

    with pytest.raises(DemoError, match="not empty or demo-owned"):
        prepare_output_dir(existing, clean=False)

    assert keep.read_text(encoding="utf-8") == "do not overwrite\n"


def test_prepare_output_dir_cleans_owned_directory(tmp_path: Path) -> None:
    out_dir = prepare_output_dir(tmp_path / "demo", clean=True)
    stale = out_dir / "stale.txt"
    stale.write_text("old\n", encoding="utf-8")

    prepared = prepare_output_dir(out_dir, clean=True)

    assert prepared == out_dir
    assert not stale.exists()
    marker = out_dir / DEMO_MARKER_FILENAME
    assert json.loads(marker.read_text(encoding="utf-8")) == {"owner": "agent-assure-demo"}


@pytest.mark.parametrize(
    "marker_payload",
    (
        ('{"nested":' * 81) + "null" + ("}" * 81),
        " " * (MAX_DEMO_MARKER_BYTES + 1),
    ),
)
def test_prepare_output_dir_treats_unbounded_marker_as_unowned(
    tmp_path: Path,
    marker_payload: str,
) -> None:
    out_dir = tmp_path / "demo"
    out_dir.mkdir()
    marker = out_dir / DEMO_MARKER_FILENAME
    keep = out_dir / "keep.txt"
    marker.write_text(marker_payload, encoding="utf-8")
    keep.write_text("keep", encoding="utf-8")

    with pytest.raises(DemoError, match="without agent-assure demo ownership marker"):
        prepare_output_dir(out_dir, clean=True)

    assert keep.read_text(encoding="utf-8") == "keep"


def test_prepare_output_dir_cleans_legacy_demo_directory(tmp_path: Path) -> None:
    out_dir = tmp_path / "demo"
    out_dir.mkdir()
    stale = out_dir / "demo-summary.json"
    stale.write_text("{}\n", encoding="utf-8")

    prepared = prepare_output_dir(out_dir, clean=True)

    assert prepared == out_dir
    assert not stale.exists()
    assert (out_dir / DEMO_MARKER_FILENAME).is_file()


def test_command_metadata_redacts_absolute_paths(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    inside = root / "runset.json"
    outside = tmp_path / "outside.json"
    result = ExpectedCommandResult(
        name="example",
        expected_exit_codes={0},
        actual_exit_code=0,
        command=(sys.executable, "-m", "agent_assure.cli.main", str(inside), str(outside)),
    )

    payload = result.model_dump(root=root)

    assert payload["command"] == [
        "<python>",
        "-m",
        "agent_assure.cli.main",
        "runset.json",
        "<absolute-path:outside.json>",
    ]
    assert str(tmp_path) not in json.dumps(payload)


def test_demo_subprocess_env_blocks_child_process_network(tmp_path: Path) -> None:
    env = demo_subprocess_env(tmp_path, env=os.environ.copy())
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import socket; socket.create_connection(('127.0.0.1', 9))",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "network access is disabled for agent-assure demo subprocesses" in result.stderr


def test_run_cli_command_records_timeout_logs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def timeout_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd=["python"],
            timeout=1,
            output="partial stdout",
            stderr="partial stderr",
        )

    monkeypatch.setattr(subprocess, "run", timeout_run)

    with pytest.raises(DemoError, match="exceeded 1 second timeout"):
        run_cli_command(
            name="slow",
            args=["--version"],
            out_dir=tmp_path,
            expected_exit_codes={0},
            cwd=tmp_path,
            timeout_seconds=1,
        )

    assert (tmp_path / "logs" / "slow.stdout.txt").read_text(encoding="utf-8") == ("partial stdout")
    assert (tmp_path / "logs" / "slow.stderr.txt").read_text(encoding="utf-8") == ("partial stderr")
