from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from agent_assure.authoring.yaml_nodes import load_yaml_nodes
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.live.config import load_live_run_config
from agent_assure.rag.repeated_sensitivity import load_repeated_sensitivity_protocol
from agent_assure.rag.sensitivity import load_knowledge_contract


@pytest.mark.parametrize(
    ("filename", "loader"),
    (
        ("suite.yaml", load_yaml_nodes),
        ("compiled-suite.json", load_compiled_suite),
        ("knowledge-contract.yaml", load_knowledge_contract),
        ("live-run.yaml", load_live_run_config),
        ("repeated-protocol.yaml", load_repeated_sensitivity_protocol),
        ("repeated-protocol.json", load_repeated_sensitivity_protocol),
    ),
)
def test_authored_inputs_reject_linked_intermediate_directory(
    tmp_path: Path,
    filename: str,
    loader: Callable[[Path], object],
) -> None:
    target = tmp_path / "target"
    linked = tmp_path / "linked"
    target.mkdir()
    (target / filename).write_text("{}\\n", encoding="utf-8")
    _create_directory_link(linked, target)

    with pytest.raises((OSError, ValueError)) as exc_info:
        loader(linked / filename)

    messages: list[str] = []
    error: BaseException | None = exc_info.value
    while error is not None:
        messages.append(str(error).lower())
        error = error.__cause__
    assert any(
        marker in message
        for message in messages
        for marker in ("link", "reparse point", "rooted file", "directory")
    )


def _create_directory_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except OSError as symlink_error:
        if os.name != "nt":
            pytest.skip(f"directory symlinks unavailable: {symlink_error}")
    command_processor = os.environ.get("COMSPEC", "cmd.exe")
    result = subprocess.run(
        [command_processor, "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(
            "directory symlinks and junctions unavailable: "
            + (result.stderr.strip() or result.stdout.strip())
        )
