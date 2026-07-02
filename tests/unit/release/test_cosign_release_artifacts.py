from __future__ import annotations

from pathlib import Path

from scripts.cosign_release_artifacts import release_artifacts, workflow_identity


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
