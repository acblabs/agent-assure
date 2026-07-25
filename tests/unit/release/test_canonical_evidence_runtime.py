from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CANONICAL_EVIDENCE_PYTHON = "3.14.6"


def test_release_and_evidence_workflows_pin_one_exact_runtime() -> None:
    for relative_path in (
        ".github/workflows/evidence.yml",
        ".github/workflows/publish-testpypi.yml",
        ".github/workflows/release.yml",
    ):
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        assert (
            f'PYTHON_VERSION: "{CANONICAL_EVIDENCE_PYTHON}"' in text
        ), relative_path


def test_dependency_locking_names_the_canonical_evidence_runtime() -> None:
    locking_text = (ROOT / "docs/dependency_locking.md").read_text(encoding="utf-8")
    runbook_text = (ROOT / "docs/release_pypi.md").read_text(encoding="utf-8")
    normalized_locking = " ".join(locking_text.split())
    normalized_runbook = " ".join(runbook_text.split())

    assert f"Python {CANONICAL_EVIDENCE_PYTHON}" in normalized_locking
    assert "canonical producer for release and evidence workflows" in normalized_locking
    assert f"Python {CANONICAL_EVIDENCE_PYTHON} canonical" in normalized_runbook


def test_final_pypi_smoke_checks_install_current_project_version() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = project["project"]["version"]
    runbook = (ROOT / "docs/release_pypi.md").read_text(encoding="utf-8")
    final_release = runbook.split("## Final PyPI Release", maxsplit=1)[1]

    assert final_release.count(f"python -m pip install agent-assure=={version}") == 2
