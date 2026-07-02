from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from scripts.smoke_install_wheel import _demo_network_guard_assertion

ROOT = Path(__file__).resolve().parents[3]


def test_demo_network_guard_assertion_blocks_socket_in_child(tmp_path: Path) -> None:
    env = os.environ.copy()
    pythonpath = [str(ROOT / "src")]
    if env.get("PYTHONPATH"):
        pythonpath.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)

    result = subprocess.run(
        [sys.executable, "-c", _demo_network_guard_assertion()],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
