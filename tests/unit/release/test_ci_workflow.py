from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_adk_smoke_installs_locked_dependency_and_cannot_silently_skip() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    adk_job = workflow.split("  adk-smoke:\n", maxsplit=1)[1]

    assert "pip install --require-hashes -r requirements-adk.lock" in adk_job
    assert "from google.adk.events.event import Event" in adk_job
    assert "from google.adk.events.event_actions import EventActions" in adk_job
    assert 'pip install --no-deps --no-build-isolation ".[adk]"' not in adk_job

    lockfile = (ROOT / "requirements-adk.lock").read_text(encoding="utf-8")
    assert "\ngoogle-adk==" in lockfile


def test_testpypi_schema_checks_have_full_history_and_cannot_silently_skip() -> None:
    workflow = (ROOT / ".github" / "workflows" / "publish-testpypi.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("fetch-depth: 0") == 2
    assert (
        workflow.count(
            "python scripts/check_tagged_schema_immutability.py --require-release-tags"
        )
        == 2
    )
