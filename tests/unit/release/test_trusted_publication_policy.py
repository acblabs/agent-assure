from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[3]
RUNBOOK = ROOT / "docs" / "release_pypi.md"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
TESTPYPI_WORKFLOW = ROOT / ".github" / "workflows" / "publish-testpypi.yml"

DOWNLOAD_ACTION = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
PUBLISH_ACTION = "pypa/gh-action-pypi-publish@cef221092ed1bacb1cc03d23a2d87d1d172e277b"


def _workflow_jobs(path: Path) -> dict[str, dict[str, Any]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    return cast(dict[str, dict[str, Any]], document["jobs"])


def _assert_minimal_oidc_publisher(
    job: dict[str, Any],
    *,
    environment: str,
    needs: list[str],
    artifact_id: str,
) -> None:
    assert job["needs"] == needs
    assert job["environment"]["name"] == environment
    assert job["permissions"] == {"id-token": "write"}
    assert "continue-on-error" not in job

    steps = job["steps"]
    assert len(steps) == 2
    download, publish = steps
    assert download["uses"] == DOWNLOAD_ACTION
    assert download["with"]["artifact-ids"] == artifact_id
    assert download["with"]["merge-multiple"] is True
    assert download["with"]["path"] == "dist"
    assert publish["uses"] == PUBLISH_ACTION
    assert publish["with"]["packages-dir"] == "dist"

    serialized = json.dumps(job, sort_keys=True).lower()
    assert "actions/checkout@" not in serialized
    assert "actions/setup-python@" not in serialized
    assert '"run"' not in serialized
    assert '"password"' not in serialized
    assert '"username"' not in serialized
    assert "secrets." not in serialized


def test_release_runbook_prohibits_local_credential_publication() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")
    normalized = " ".join(runbook.split())

    forbidden_authorization_patterns = (
        r"\btwine\s+upload\b",
        r"\b__token__\b",
        r"\bmanual fallback\b",
        r"\bmanual (?:final )?(?:pypi|testpypi) upload\b",
        r"\buse a pypi api token\b",
        r"\baccount-scoped token may be required\b",
        r"\bupload the package files from\b",
    )
    for pattern in forbidden_authorization_patterns:
        assert re.search(pattern, runbook, flags=re.IGNORECASE) is None, pattern

    assert "Every TestPyPI and PyPI upload uses GitHub Trusted Publishing with OIDC" in normalized
    assert "Local credential-based upload is prohibited" in normalized
    assert "publication is blocked" in normalized
    assert "rerun the failed publisher job from the same workflow run" in normalized
    assert "use only an applicable recovery operation already declared" in normalized
    assert "Revoke legacy TestPyPI and PyPI upload tokens" in normalized


def test_standard_pypi_publisher_is_oidc_only_and_artifact_bound() -> None:
    jobs = _workflow_jobs(RELEASE_WORKFLOW)

    _assert_minimal_oidc_publisher(
        jobs["pypi-publish"],
        environment="pypi",
        needs=["verify-uploaded-artifacts", "attest-release-provenance", "github-release"],
        artifact_id="${{ needs.verify-uploaded-artifacts.outputs.distributions_artifact_id }}",
    )


def test_testpypi_publisher_is_oidc_only_and_gate_bound() -> None:
    jobs = _workflow_jobs(TESTPYPI_WORKFLOW)
    required_gates = [
        "build",
        "reproduce",
        "candidate-security",
        "candidate-lower-bounds",
        "candidate-platform-audit",
    ]

    _assert_minimal_oidc_publisher(
        jobs["testpypi-publish"],
        environment="testpypi",
        needs=required_gates,
        artifact_id="${{ needs.build.outputs.distributions_artifact_id }}",
    )
    assert jobs["testpypi-publish"]["steps"][1]["with"]["repository-url"] == (
        "https://test.pypi.org/legacy/"
    )


def test_historical_recovery_publisher_remains_oidc_only_and_artifact_bound() -> None:
    jobs = _workflow_jobs(RELEASE_WORKFLOW)
    recovery = jobs["recover-pypi-publish"]

    _assert_minimal_oidc_publisher(
        recovery,
        environment="pypi",
        needs=["recover-verify", "recover-github-release"],
        artifact_id="${{ needs.recover-verify.outputs.distributions_artifact_id }}",
    )
    condition = recovery["if"]
    assert "needs.recover-verify.result == 'success'" in condition
    assert "needs.recover-github-release.result == 'success'" in condition
    assert "inputs.operation == 'recover-v0.6.0'" in condition
    assert "github.ref == 'refs/tags/release-recovery/v0.6.0-30170334180'" in condition
