from __future__ import annotations

from pathlib import Path

from scripts.cosign_release_artifacts import release_artifacts, workflow_identity

ROOT = Path(__file__).resolve().parents[3]


def test_release_artifacts_include_fixed_files_and_distributions(tmp_path: Path) -> None:
    release_dir = tmp_path / "release"
    reports = release_dir / "reports"
    dist = release_dir / "dist"
    reports.mkdir(parents=True)
    dist.mkdir()
    for path in (
        reports / "evidence-packet.json",
        reports / "release-artifact-manifest.json",
        release_dir / "release-digest-replay.json",
        release_dir / "sbom.cdx.json",
        dist / "agent_assure-0.3.0-py3-none-any.whl",
        dist / "agent_assure-0.3.0.tar.gz",
    ):
        path.write_text("{}\n", encoding="utf-8")
    (dist / "agent_assure-0.3.0.tar.gz.bundle").write_text("bundle\n", encoding="utf-8")

    artifacts = release_artifacts(release_dir)

    assert dist / "agent_assure-0.3.0.tar.gz.bundle" not in artifacts
    assert artifacts == (
        reports / "evidence-packet.json",
        reports / "release-artifact-manifest.json",
        release_dir / "release-digest-replay.json",
        release_dir / "sbom.cdx.json",
        dist / "agent_assure-0.3.0-py3-none-any.whl",
        dist / "agent_assure-0.3.0.tar.gz",
    )


def test_release_artifacts_reports_missing_required_file(tmp_path: Path) -> None:
    release_dir = tmp_path / "release"
    (release_dir / "reports").mkdir(parents=True)

    try:
        release_artifacts(release_dir)
    except RuntimeError as exc:
        assert "missing release artifact" in str(exc)
        assert "evidence-packet.json" in str(exc)
    else:
        raise AssertionError("expected missing artifacts to fail")


def test_workflow_identity_uses_reviewed_github_shape() -> None:
    assert (
        workflow_identity(
            repository="acblabs/agent-assure",
            workflow_path=".github/workflows/release.yml",
            ref="refs/tags/v0.3.0",
        )
        == "https://github.com/acblabs/agent-assure/.github/workflows/release.yml"
        "@refs/tags/v0.3.0"
    )


def test_pypi_publish_verifies_signatures_before_replay() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    pypi_job = workflow[workflow.index("  pypi-publish:") :]

    signature_index = pypi_job.index(
        "\n      - name: Verify downloaded release bundle signatures\n"
    )
    replay_index = pypi_job.index("\n      - name: Verify downloaded release bundle\n")
    stage_index = pypi_job.index("\n      - name: Stage PyPI package files\n")

    assert signature_index < replay_index < stage_index
    signature_step = pypi_job[signature_index:replay_index]
    assert "python scripts/cosign_release_artifacts.py verify" in signature_step
    assert "--workflow-name release" in signature_step
    assert "--workflow-path .github/workflows/release.yml" in signature_step


def test_release_workflow_uses_canonical_release_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    build_job = workflow[: workflow.index("  pypi-publish:")]

    assert "\n      - run: make release-check\n" in build_job
    assert "\n      - run: python scripts/update_golden.py\n" in build_job
    assert "\n      - run: mypy src\n" not in build_job


def test_testpypi_build_uses_locked_editable_install() -> None:
    workflow = (ROOT / ".github" / "workflows" / "publish-testpypi.yml").read_text(
        encoding="utf-8"
    )
    build_job = workflow[: workflow.index("  testpypi-publish:")]

    lock_index = build_job.index(
        "\n      - run: python -m pip install --require-hashes -r requirements.lock\n"
    )
    editable_index = build_job.index(
        "\n      - run: python -m pip install --no-deps --no-build-isolation -e .\n"
    )

    assert lock_index < editable_index
    assert 'python -m pip install ".[dev]"' not in build_job
