from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import scripts.cosign_release_artifacts as cosign_script
from agent_assure.artifact_io import git_output
from agent_assure.cli.main import app
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.release_evidence import build_digest_replay, write_digest_replay
from agent_assure.reporting.environment import (
    build_release_manifest,
    release_artifact,
    write_release_manifest,
)
from agent_assure.reporting.packet import (
    load_evidence_packet,
    write_evidence_packet,
    write_evidence_packet_markdown,
)
from agent_assure.reporting.sbom import build_sbom, write_sbom
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from scripts.assert_dist_reproducible import stage_verified_release_bundle
from scripts.cosign_release_artifacts import release_artifacts, workflow_identity

ROOT = Path(__file__).resolve().parents[3]
RUNNER = CliRunner()


def test_release_artifacts_include_fixed_files_and_distributions(tmp_path: Path) -> None:
    release_dir = tmp_path / "release"
    reports = release_dir / "reports"
    dist = release_dir / "dist"
    reports.mkdir(parents=True)
    dist.mkdir()
    for path in (
        reports / "evidence-packet.json",
        reports / "evidence-packet.md",
        reports / "evaluation-summary.json",
        reports / "comparison-summary.json",
        reports / "assurance-evidence-graph.json",
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
        reports / "evidence-packet.md",
        reports / "evaluation-summary.json",
        reports / "comparison-summary.json",
        reports / "assurance-evidence-graph.json",
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
        assert "evaluation-summary.json" in str(exc)
        assert "comparison-summary.json" in str(exc)
        assert "assurance-evidence-graph.json" in str(exc)
    else:
        raise AssertionError("expected missing artifacts to fail")


def test_release_artifacts_reject_unexpected_distribution_file(tmp_path: Path) -> None:
    release_dir = tmp_path / "release"
    reports = release_dir / "reports"
    dist = release_dir / "dist"
    reports.mkdir(parents=True)
    dist.mkdir()
    for path in (
        reports / "evidence-packet.json",
        reports / "evidence-packet.md",
        reports / "evaluation-summary.json",
        reports / "comparison-summary.json",
        reports / "assurance-evidence-graph.json",
        reports / "release-artifact-manifest.json",
        release_dir / "release-digest-replay.json",
        release_dir / "sbom.cdx.json",
        dist / "agent_assure-0.6.0-py3-none-any.whl",
        dist / "agent_assure-0.6.0.tar.gz",
        dist / "unexpected.zip",
    ):
        path.write_text("{}\n", encoding="utf-8")

    try:
        release_artifacts(release_dir)
    except RuntimeError as exc:
        assert "invalid release distribution set" in str(exc)
        assert "unexpected.zip" in str(exc)
    else:
        raise AssertionError("expected an extra distribution file to fail")


def test_verify_rejects_mixed_stable_equivalent_bundles_after_signatures_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_a = tmp_path / "bundle-a"
    bundle_b = tmp_path / "bundle-b"
    mixed = tmp_path / "mixed"
    _write_bound_signing_bundle(bundle_a, platform="Linux-a")
    _write_bound_signing_bundle(bundle_b, platform="Linux-b")
    packet_a = load_evidence_packet(bundle_a / "reports" / "evidence-packet.json")
    packet_b = load_evidence_packet(bundle_b / "reports" / "evidence-packet.json")
    assert packet_a.packet_id == packet_b.packet_id
    assert packet_a.evaluation.environment != packet_b.evaluation.environment
    assert _stable_review_digests(bundle_a) == _stable_review_digests(bundle_b)
    cosign_script.verify_release_bundle_bindings(bundle_a)
    cosign_script.verify_release_bundle_bindings(bundle_b)

    manifest_mixed = tmp_path / "manifest-mixed"
    shutil.copytree(bundle_a, manifest_mixed)
    shutil.copy2(
        bundle_b / "reports" / "release-artifact-manifest.json",
        manifest_mixed / "reports" / "release-artifact-manifest.json",
    )
    with pytest.raises(
        RuntimeError,
        match="manifest does not match the manifest nested in the evidence packet",
    ):
        cosign_script.verify_release_bundle_bindings(manifest_mixed)

    shutil.copytree(bundle_a, mixed)
    for relative_path in (
        "reports/evaluation-summary.json",
        "reports/comparison-summary.json",
        "reports/assurance-evidence-graph.json",
        "reports/release-artifact-manifest.json",
    ):
        shutil.copy2(bundle_b / relative_path, mixed / relative_path)

    verified: list[Path] = []

    def _verified_blob(
        artifact: Path,
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        verified.append(artifact)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(cosign_script, "verify_blob", _verified_blob)
    with pytest.raises(
        RuntimeError,
        match="evaluation-summary source file digest does not match release manifest",
    ):
        cosign_script.verify_artifacts(
            mixed,
            cosign="cosign",
            workflow_name="release",
            workflow_path=".github/workflows/release.yml",
            repository="acblabs/agent-assure",
            ref="refs/tags/v0.6.3",
            sha="1" * 40,
            event_name="push",
            issuer=cosign_script.DEFAULT_ISSUER,
        )

    assert verified == list(release_artifacts(mixed))


def test_verify_rejects_each_mixed_signed_asset_after_signatures_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_a = tmp_path / "bundle-a-complete"
    bundle_b = tmp_path / "bundle-b-complete"
    _write_bound_signing_bundle(bundle_a, platform="Linux-a", variant_marker="a")
    _write_bound_signing_bundle(bundle_b, platform="Linux-b", variant_marker="b")
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None
    expected = {
        "expected_ref": "refs/tags/v0.6.3",
        "expected_sha": current_sha,
        "require_release_notes": True,
    }
    expected_notes = (ROOT / "docs/release_notes/v0.6.3.md").read_bytes()
    monkeypatch.setattr(
        cosign_script,
        "git_file_bytes",
        lambda *_args, **_kwargs: expected_notes,
    )
    cosign_script.verify_release_bundle_bindings(bundle_a, **expected)
    cosign_script.verify_release_bundle_bindings(bundle_b, **expected)

    # Notes are source-bound instead of rerun-derived. Make the second signed blob
    # adversarial so the immutable-Git-note edge is exercised as well.
    (bundle_b / "release-notes.md").write_bytes(b"# substituted release notes\n")
    source_artifacts = release_artifacts(bundle_a)
    substituted_by_path = {path.relative_to(bundle_b): path for path in release_artifacts(bundle_b)}
    assert {path.relative_to(bundle_a) for path in source_artifacts} == set(substituted_by_path)
    for source_path in source_artifacts:
        relative_path = source_path.relative_to(bundle_a)
        assert source_path.read_bytes() != substituted_by_path[relative_path].read_bytes()

    verified: list[Path] = []

    def _verified_blob(
        artifact: Path,
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        verified.append(artifact)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(cosign_script, "verify_blob", _verified_blob)
    for source_path in source_artifacts:
        relative_path = source_path.relative_to(bundle_a)
        mixed = tmp_path / f"mixed-{source_path.name}"
        shutil.copytree(bundle_a, mixed)
        shutil.copy2(substituted_by_path[relative_path], mixed / relative_path)

        verified.clear()
        with pytest.raises(RuntimeError, match="release (?:evidence bundle|signed-set)"):
            cosign_script.verify_artifacts(
                mixed,
                cosign="cosign",
                workflow_name="release",
                workflow_path=".github/workflows/release.yml",
                repository="acblabs/agent-assure",
                ref="refs/tags/v0.6.3",
                sha=current_sha,
                event_name="push",
                issuer=cosign_script.DEFAULT_ISSUER,
                require_release_notes=True,
            )
        assert verified == list(release_artifacts(mixed))


def test_official_staged_bundle_carries_full_replay_support(tmp_path: Path) -> None:
    rebuilt = tmp_path / "rebuilt"
    staged = tmp_path / "verified-release"
    _write_bound_signing_bundle(rebuilt, platform="Linux", variant_marker="staged")
    unrelated = rebuilt / "logs" / "command.log"
    unrelated.parent.mkdir()
    unrelated.write_text("not verification evidence\n", encoding="utf-8")

    stage_verified_release_bundle(
        rebuilt,
        staged,
        require_release_notes=True,
    )

    for relative_path in (
        "prior-auth.compiled.json",
        "prior-auth.fixtures.json",
        "reports/dependency-inventory.json",
    ):
        assert (staged / relative_path).read_bytes() == (rebuilt / relative_path).read_bytes()
    assert not (staged / "logs").exists()
    assert {path.relative_to(staged) for path in release_artifacts(staged)} == {
        path.relative_to(rebuilt) for path in release_artifacts(rebuilt)
    }
    cosign_script.verify_release_bundle_bindings(staged)


def test_staging_rejects_symlinked_replay_support(tmp_path: Path) -> None:
    rebuilt = tmp_path / "rebuilt-symlink"
    staged = tmp_path / "verified-symlink"
    _write_bound_signing_bundle(rebuilt, platform="Linux")
    compiled = rebuilt / "prior-auth.compiled.json"
    target = rebuilt / "prior-auth.compiled.real.json"
    compiled.replace(target)
    try:
        compiled.symlink_to(target.name)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    with pytest.raises(ValueError, match="must be a regular file"):
        stage_verified_release_bundle(
            rebuilt,
            staged,
            require_release_notes=True,
        )

    assert not staged.exists()


def test_verify_and_promote_materializes_exact_full_and_pypi_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux", variant_marker="promoted")
    _write_fake_signature_bundles(release_dir)
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None
    monkeypatch.setattr(
        cosign_script,
        "verify_blob",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(
        cosign_script,
        "git_file_bytes",
        lambda *_args, **_kwargs: (release_dir / "release-notes.md").read_bytes(),
    )

    cosign_script.verify_and_promote_artifacts(
        release_dir,
        promotion_dir=promotion_dir,
        cosign="cosign",
        workflow_name="release",
        workflow_path=".github/workflows/release.yml",
        repository="acblabs/agent-assure",
        ref="refs/tags/v0.6.3",
        sha=current_sha,
        event_name="push",
        issuer=cosign_script.DEFAULT_ISSUER,
        require_release_notes=True,
    )

    promoted_release = promotion_dir / "release"
    promoted_distributions = promotion_dir / "distributions"
    signable_paths = {
        path.relative_to(release_dir).as_posix() for path in release_artifacts(release_dir)
    }
    expected_full_paths = {
        *signable_paths,
        *(f"{path}.bundle" for path in signable_paths),
        "prior-auth.compiled.json",
        "prior-auth.fixtures.json",
        "reports/dependency-inventory.json",
    }
    actual_full_paths = {
        path.relative_to(promoted_release).as_posix()
        for path in promoted_release.rglob("*")
        if path.is_file()
    }
    assert actual_full_paths == expected_full_paths
    distribution_names = {
        "agent_assure-0.6.3-py3-none-any.whl",
        "agent_assure-0.6.3.tar.gz",
    }
    assert {path.name for path in promoted_distributions.iterdir()} == distribution_names
    for name in distribution_names:
        assert (promoted_distributions / name).read_bytes() == (
            promoted_release / "dist" / name
        ).read_bytes()
    cosign_script.verify_release_bundle_bindings(
        promoted_release,
        expected_ref="refs/tags/v0.6.3",
        expected_sha=current_sha,
        require_release_notes=True,
    )


def test_verify_and_promote_handles_official_project_relative_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "checkout"
    release_dir = project_root / ".tmp" / "release"
    promotion_dir = project_root / ".tmp" / "verified-promotion"
    _write_bound_signing_bundle(
        release_dir,
        platform="Linux",
        variant_marker="project-relative",
        project_root=project_root,
    )
    _write_fake_signature_bundles(release_dir)
    packet = load_evidence_packet(release_dir / "reports" / "evidence-packet.json")
    assert packet.release_manifest is not None
    graph = next(
        artifact
        for artifact in packet.release_manifest.artifacts
        if artifact.role == "assurance-evidence-graph"
    )
    assert graph.path == ".tmp/release/reports/assurance-evidence-graph.json"
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None
    monkeypatch.setattr(
        cosign_script,
        "verify_blob",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(
        cosign_script,
        "git_file_bytes",
        lambda *_args, **_kwargs: (release_dir / "release-notes.md").read_bytes(),
    )

    cosign_script.verify_and_promote_artifacts(
        release_dir,
        promotion_dir=promotion_dir,
        cosign="cosign",
        workflow_name="release",
        workflow_path=".github/workflows/release.yml",
        repository="acblabs/agent-assure",
        ref="refs/tags/v0.6.3",
        sha=current_sha,
        event_name="push",
        issuer=cosign_script.DEFAULT_ISSUER,
        require_release_notes=True,
    )

    assert (promotion_dir / "release" / graph.path.removeprefix(".tmp/release/")).is_file()
    assert len(tuple((promotion_dir / "distributions").iterdir())) == 2


@pytest.mark.parametrize("extra_kind", ("file", "empty-directory"))
def test_verify_and_promote_rejects_extra_full_tree_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra_kind: str,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    if extra_kind == "file":
        (release_dir / "unsigned-extra.txt").write_text("extra\n", encoding="utf-8")
    else:
        (release_dir / "empty-extra-directory").mkdir()
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises(RuntimeError, match="release tree inventory mismatch"):
        _verify_and_promote_fixture(
            release_dir,
            promotion_dir=promotion_dir,
            current_sha=current_sha,
        )

    assert not promotion_dir.exists()


@pytest.mark.parametrize(
    "relative_path",
    (
        "prior-auth.compiled.json",
        "reports/evaluation-summary.json.bundle",
    ),
)
def test_verify_and_promote_rejects_missing_full_tree_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    (release_dir / relative_path).unlink()
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises((OSError, RuntimeError, ValueError)):
        _verify_and_promote_fixture(
            release_dir,
            promotion_dir=promotion_dir,
            current_sha=current_sha,
        )

    assert not promotion_dir.exists()


def test_verify_and_promote_rejects_dangling_extra_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    link = release_dir / "dangling-extra"
    try:
        link.symlink_to("missing-target")
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises(ValueError, match="link or reparse point: dangling-extra"):
        _verify_and_promote_fixture(
            release_dir,
            promotion_dir=promotion_dir,
            current_sha=current_sha,
        )

    assert not promotion_dir.exists()


def test_verify_and_promote_rejects_expected_file_symlink_with_same_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    summary = release_dir / "reports" / "evaluation-summary.json"
    external_summary = tmp_path / "evaluation-summary.json"
    shutil.copyfile(summary, external_summary)
    summary.unlink()
    try:
        summary.symlink_to(external_summary)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises(ValueError, match="link or reparse point"):
        _verify_and_promote_fixture(
            release_dir,
            promotion_dir=promotion_dir,
            current_sha=current_sha,
        )

    assert not promotion_dir.exists()


def test_verify_and_promote_rejects_linked_reports_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    reports = release_dir / "reports"
    external_reports = tmp_path / "external-reports"
    shutil.copytree(reports, external_reports)
    shutil.rmtree(reports)
    _create_directory_link(reports, external_reports)
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )
    try:
        with pytest.raises((OSError, RuntimeError, ValueError), match="link|reparse"):
            _verify_and_promote_fixture(
                release_dir,
                promotion_dir=promotion_dir,
                current_sha=current_sha,
            )
    finally:
        _remove_directory_link(reports)

    assert not promotion_dir.exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_verify_and_promote_rejects_fifo_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    os.mkfifo(release_dir / "unexpected-fifo")
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises(ValueError, match="regular file or directory: unexpected-fifo"):
        _verify_and_promote_fixture(
            release_dir,
            promotion_dir=promotion_dir,
            current_sha=current_sha,
        )

    assert not promotion_dir.exists()


def test_release_tree_inventory_rejects_windows_reparse_attribute() -> None:
    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG,
        st_file_attributes=cosign_script._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
    )

    assert cosign_script._metadata_is_link_or_reparse(metadata)


@pytest.mark.parametrize(
    "relative_path",
    (
        "reports/evaluation-summary.json",
        "reports/evaluation-summary.json.bundle",
        "prior-auth.compiled.json",
        "dist/agent_assure-0.6.3-py3-none-any.whl",
        "dist/agent_assure-0.6.3.tar.gz",
    ),
)
def test_verify_and_promote_rejects_mutation_between_verification_and_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux", variant_marker="sealed")
    _write_fake_signature_bundles(release_dir)
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None
    monkeypatch.setattr(
        cosign_script,
        "verify_blob",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(
        cosign_script,
        "git_file_bytes",
        lambda *_args, **_kwargs: (release_dir / "release-notes.md").read_bytes(),
    )
    original_verify_bindings = cosign_script.verify_release_bundle_bindings

    def verify_then_mutate(
        staged_release: Path,
        **kwargs: object,
    ) -> None:
        original_verify_bindings(staged_release, **kwargs)
        target = staged_release / Path(relative_path)
        target.write_bytes(target.read_bytes() + b"\nmutated after verification\n")

    monkeypatch.setattr(
        cosign_script,
        "verify_release_bundle_bindings",
        verify_then_mutate,
    )

    with pytest.raises(RuntimeError, match="changed before promotion"):
        cosign_script.verify_and_promote_artifacts(
            release_dir,
            promotion_dir=promotion_dir,
            cosign="cosign",
            workflow_name="release",
            workflow_path=".github/workflows/release.yml",
            repository="acblabs/agent-assure",
            ref="refs/tags/v0.6.3",
            sha=current_sha,
            event_name="push",
            issuer=cosign_script.DEFAULT_ISSUER,
            require_release_notes=True,
        )

    assert not promotion_dir.exists()


def test_verify_and_promote_rejects_extra_entry_added_after_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )
    original_verify_bindings = cosign_script.verify_release_bundle_bindings

    def verify_then_add_extra(
        staged_release: Path,
        **kwargs: object,
    ) -> None:
        original_verify_bindings(staged_release, **kwargs)
        (staged_release / "unsigned-extra.txt").write_text(
            "injected after verification\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(
        cosign_script,
        "verify_release_bundle_bindings",
        verify_then_add_extra,
    )

    with pytest.raises(RuntimeError, match="extra file.*unsigned-extra.txt"):
        _verify_and_promote_fixture(
            release_dir,
            promotion_dir=promotion_dir,
            current_sha=current_sha,
        )

    assert not promotion_dir.exists()


@pytest.mark.parametrize(
    "relative_path",
    (
        "prior-auth.compiled.json",
        "reports/evaluation-summary.json.bundle",
    ),
)
def test_verify_and_promote_rejects_entry_removed_after_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )
    original_verify_bindings = cosign_script.verify_release_bundle_bindings

    def verify_then_remove_entry(
        staged_release: Path,
        **kwargs: object,
    ) -> None:
        original_verify_bindings(staged_release, **kwargs)
        (staged_release / relative_path).unlink()

    monkeypatch.setattr(
        cosign_script,
        "verify_release_bundle_bindings",
        verify_then_remove_entry,
    )

    with pytest.raises(RuntimeError, match="missing file"):
        _verify_and_promote_fixture(
            release_dir,
            promotion_dir=promotion_dir,
            current_sha=current_sha,
        )

    assert not promotion_dir.exists()


@pytest.mark.parametrize("entry_point", ("verify-and-promote", "verify-uploaded"))
def test_cleanup_failure_does_not_mask_primary_verification_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_point: str,
) -> None:
    release_dir = tmp_path / "release"
    promotion_dir = tmp_path / "verified-promotion"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None

    def fail_verification(*_args: object, **_kwargs: object) -> None:
        raise ValueError("signature verification failed")

    def fail_cleanup(*_args: object, **_kwargs: object) -> None:
        raise OSError("cleanup denied")

    monkeypatch.setattr(
        cosign_script,
        "_verify_staged_release_snapshot",
        fail_verification,
    )
    monkeypatch.setattr(cosign_script.shutil, "rmtree", fail_cleanup)

    with pytest.raises(ValueError, match="signature verification failed") as caught:
        if entry_point == "verify-and-promote":
            _verify_and_promote_fixture(
                release_dir,
                promotion_dir=promotion_dir,
                current_sha=current_sha,
            )
        else:
            _verify_uploaded_fixture(
                release_dir,
                distributions_dir=None,
                current_sha=current_sha,
            )

    notes = getattr(caught.value, "__notes__", ())
    assert len(notes) == 1
    assert "private workspace cleanup also failed" in notes[0]
    assert "cleanup denied" in notes[0]


def test_cleanup_failure_after_success_remains_fatal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None

    monkeypatch.setattr(
        cosign_script,
        "_verify_staged_release_snapshot",
        lambda *_args, **_kwargs: None,
    )

    def fail_cleanup(*_args: object, **_kwargs: object) -> None:
        raise OSError("cleanup denied")

    monkeypatch.setattr(cosign_script.shutil, "rmtree", fail_cleanup)

    with pytest.raises(
        RuntimeError,
        match="could not remove private promotion workspace",
    ) as caught:
        _verify_uploaded_fixture(
            release_dir,
            distributions_dir=None,
            current_sha=current_sha,
        )

    assert isinstance(caught.value.__cause__, OSError)
    assert str(caught.value.__cause__) == "cleanup denied"


def test_main_renders_exception_notes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_verification(*_args: object, **_kwargs: object) -> None:
        error = RuntimeError("signature verification failed")
        error.add_note("private workspace cleanup also failed: cleanup denied")
        raise error

    monkeypatch.setattr(cosign_script, "verify_artifacts", fail_verification)

    result = cosign_script.main(
        [
            "verify",
            "--release-dir",
            str(tmp_path),
            "--workflow-name",
            "release",
            "--workflow-path",
            ".github/workflows/release.yml",
        ]
    )

    assert result == 1
    assert capsys.readouterr().err.splitlines() == [
        "cosign-release-artifacts: signature verification failed",
        "cosign-release-artifacts: note: private workspace cleanup also failed: cleanup denied",
    ]


def test_verify_uploaded_artifacts_verifies_full_tree_and_exact_distribution_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "checkout"
    release_dir = project_root / ".tmp" / "release"
    distributions_dir = project_root / ".tmp" / "distributions"
    _write_bound_signing_bundle(
        release_dir,
        platform="Linux",
        project_root=project_root,
    )
    _write_fake_signature_bundles(release_dir)
    _copy_distribution_view(release_dir, distributions_dir)
    verified: list[Path] = []
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
        verified=verified,
    )

    _verify_uploaded_fixture(
        release_dir,
        distributions_dir=distributions_dir,
        current_sha=current_sha,
    )

    assert len(verified) == len(release_artifacts(release_dir))
    assert not tuple((release_dir.parent).glob(".post-upload-verification.*"))


@pytest.mark.parametrize(
    "mutation",
    (
        "extra-file",
        "extra-sidecar",
        "extra-directory",
        "missing-wheel",
        "missing-sdist",
        "changed-wheel",
        "changed-sdist",
        "swapped-bytes",
    ),
)
def test_verify_uploaded_artifacts_rejects_nonidentical_distribution_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    release_dir = tmp_path / "release"
    distributions_dir = tmp_path / "distributions"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    wheel, sdist = _copy_distribution_view(release_dir, distributions_dir)
    if mutation == "extra-file":
        (distributions_dir / "extra.txt").write_text("extra\n", encoding="utf-8")
    elif mutation == "extra-sidecar":
        (distributions_dir / f"{wheel.name}.bundle").write_text(
            "bundle\n",
            encoding="utf-8",
        )
    elif mutation == "extra-directory":
        (distributions_dir / "empty").mkdir()
    elif mutation == "missing-wheel":
        wheel.unlink()
    elif mutation == "missing-sdist":
        sdist.unlink()
    elif mutation == "changed-wheel":
        wheel.write_bytes(wheel.read_bytes() + b"changed wheel")
    elif mutation == "changed-sdist":
        sdist.write_bytes(sdist.read_bytes() + b"changed sdist")
    else:
        wheel_bytes = wheel.read_bytes()
        sdist_bytes = sdist.read_bytes()
        wheel.write_bytes(sdist_bytes)
        sdist.write_bytes(wheel_bytes)
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises((RuntimeError, ValueError), match="distribution"):
        _verify_uploaded_fixture(
            release_dir,
            distributions_dir=distributions_dir,
            current_sha=current_sha,
        )


def test_verify_uploaded_artifacts_rejects_linked_distribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    distributions_dir = tmp_path / "distributions"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    wheel, _ = _copy_distribution_view(release_dir, distributions_dir)
    target = distributions_dir / "wheel-target"
    wheel.replace(target)
    try:
        wheel.symlink_to(target.name)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises(ValueError, match="distribution tree.*link or reparse"):
        _verify_uploaded_fixture(
            release_dir,
            distributions_dir=distributions_dir,
            current_sha=current_sha,
        )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_verify_uploaded_artifacts_rejects_distribution_fifo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    distributions_dir = tmp_path / "distributions"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    _copy_distribution_view(release_dir, distributions_dir)
    os.mkfifo(distributions_dir / "unexpected-fifo")
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises(ValueError, match="distribution tree.*regular file or directory"):
        _verify_uploaded_fixture(
            release_dir,
            distributions_dir=distributions_dir,
            current_sha=current_sha,
        )


def test_verify_uploaded_artifacts_rejects_overlapping_views(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_dir = tmp_path / "release"
    _write_bound_signing_bundle(release_dir, platform="Linux")
    _write_fake_signature_bundles(release_dir)
    current_sha = _stub_release_verification(
        monkeypatch,
        release_dir=release_dir,
    )

    with pytest.raises(ValueError, match="must be disjoint"):
        _verify_uploaded_fixture(
            release_dir,
            distributions_dir=release_dir / "dist",
            current_sha=current_sha,
        )


def test_evidence_tag_verification_does_not_require_release_notes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_bundle = tmp_path / "evidence-bundle"
    _write_bound_signing_bundle(evidence_bundle, platform="Linux")
    (evidence_bundle / "release-notes.md").unlink()
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None
    verified: list[Path] = []

    def _verified_blob(
        artifact: Path,
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        verified.append(artifact)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(cosign_script, "verify_blob", _verified_blob)
    cosign_script.verify_artifacts(
        evidence_bundle,
        cosign="cosign",
        workflow_name="evidence",
        workflow_path=".github/workflows/evidence.yml",
        repository="acblabs/agent-assure",
        ref="refs/tags/v0.6.3",
        sha=current_sha,
        event_name="push",
        issuer=cosign_script.DEFAULT_ISSUER,
    )

    assert verified == list(release_artifacts(evidence_bundle))
    assert all(path.name != "release-notes.md" for path in verified)


def test_verify_uploaded_evidence_requires_no_separate_distribution_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_bundle = tmp_path / "evidence-bundle"
    _write_bound_signing_bundle(evidence_bundle, platform="Linux")
    (evidence_bundle / "release-notes.md").unlink()
    _write_fake_signature_bundles(evidence_bundle)
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None
    verified: list[Path] = []

    def verified_blob(
        artifact: Path,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        verified.append(artifact)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(cosign_script, "verify_blob", verified_blob)
    cosign_script.verify_uploaded_artifacts(
        evidence_bundle,
        distributions_dir=None,
        cosign="cosign",
        workflow_name="evidence",
        workflow_path=".github/workflows/evidence.yml",
        repository="acblabs/agent-assure",
        ref="refs/tags/v0.6.3",
        sha=current_sha,
        event_name="push",
        issuer=cosign_script.DEFAULT_ISSUER,
    )

    assert verified
    assert all(path.name != "release-notes.md" for path in verified)


def test_release_note_binding_flag_is_workflow_specific() -> None:
    release_workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    evidence_workflow = (ROOT / ".github/workflows/evidence.yml").read_text(encoding="utf-8")
    release_verify = release_workflow.split(
        "- name: Verify exact workflow identity and atomically promote snapshots",
        maxsplit=1,
    )[1].split("- name: Upload verified distributions", maxsplit=1)[0]
    evidence_verify = evidence_workflow.split(
        "- name: Verify workflow identity and atomically promote snapshot",
        maxsplit=1,
    )[1].split("- name: Upload promoted signed evidence", maxsplit=1)[0]

    assert "--require-release-notes" in release_verify
    assert "--require-release-notes" not in evidence_verify


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


def test_signature_verification_is_unprivileged_and_precedes_publish() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    verify_job = workflow.split("  verify-signatures:\n", maxsplit=1)[1].split(
        "  verify-uploaded-artifacts:\n", maxsplit=1
    )[0]
    uploaded_verify_job = workflow.split(
        "  verify-uploaded-artifacts:\n",
        maxsplit=1,
    )[1].split("  github-release:\n", maxsplit=1)[0]
    pypi_job = workflow.split("  pypi-publish:\n", maxsplit=1)[1]

    assert "id-token: write" not in verify_job
    assert "python scripts/cosign_release_artifacts.py verify-and-promote" in verify_job
    assert "--promotion-dir .tmp/verified-promotion" in verify_job
    assert "--workflow-name release" in verify_job
    assert "--workflow-path .github/workflows/release.yml" in verify_job
    assert "id-token: write" not in uploaded_verify_job
    assert "cosign_release_artifacts.py verify-uploaded" in uploaded_verify_job
    assert "--distributions-dir .tmp/distributions" in uploaded_verify_job
    assert "actions/upload-artifact@" not in uploaded_verify_job
    assert "needs: [verify-uploaded-artifacts, github-release]" in pypi_job


def test_release_workflow_uses_canonical_release_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    build_job = workflow.split("  build:\n", maxsplit=1)[1].split("  reproduce:\n", maxsplit=1)[0]

    assert "\n      - run: make release-check EXPECTED_RELEASE=" in build_job
    assert "\n      - run: python scripts/update_golden.py\n" in build_job
    assert "\n      - run: mypy src\n" not in build_job


def test_testpypi_build_uses_locked_editable_install() -> None:
    workflow = (ROOT / ".github" / "workflows" / "publish-testpypi.yml").read_text(encoding="utf-8")
    build_job = workflow[: workflow.index("  testpypi-publish:")]

    lock_index = build_job.index(
        "\n      - run: python -m pip install --require-hashes -r requirements.lock\n"
    )
    editable_index = build_job.index(
        "\n      - run: python -m pip install --no-deps --no-build-isolation -e .\n"
    )

    assert lock_index < editable_index
    assert 'python -m pip install ".[dev]"' not in build_job


def _stub_release_verification(
    monkeypatch: pytest.MonkeyPatch,
    *,
    release_dir: Path,
    verified: list[Path] | None = None,
) -> str:
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None

    def verified_blob(
        artifact: Path,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if verified is not None:
            verified.append(artifact)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(cosign_script, "verify_blob", verified_blob)
    monkeypatch.setattr(
        cosign_script,
        "git_file_bytes",
        lambda *_args, **_kwargs: (release_dir / "release-notes.md").read_bytes(),
    )
    return current_sha


def _verify_and_promote_fixture(
    release_dir: Path,
    *,
    promotion_dir: Path,
    current_sha: str,
) -> None:
    cosign_script.verify_and_promote_artifacts(
        release_dir,
        promotion_dir=promotion_dir,
        cosign="cosign",
        workflow_name="release",
        workflow_path=".github/workflows/release.yml",
        repository="acblabs/agent-assure",
        ref="refs/tags/v0.6.3",
        sha=current_sha,
        event_name="push",
        issuer=cosign_script.DEFAULT_ISSUER,
        require_release_notes=True,
    )


def _verify_uploaded_fixture(
    release_dir: Path,
    *,
    distributions_dir: Path | None,
    current_sha: str,
) -> None:
    cosign_script.verify_uploaded_artifacts(
        release_dir,
        distributions_dir=distributions_dir,
        cosign="cosign",
        workflow_name="release",
        workflow_path=".github/workflows/release.yml",
        repository="acblabs/agent-assure",
        ref="refs/tags/v0.6.3",
        sha=current_sha,
        event_name="push",
        issuer=cosign_script.DEFAULT_ISSUER,
        require_release_notes=True,
    )


def _copy_distribution_view(
    release_dir: Path,
    distributions_dir: Path,
) -> tuple[Path, Path]:
    distributions_dir.mkdir(parents=True)
    source_wheel, source_sdist = cosign_script._distribution_artifacts(release_dir / "dist")
    wheel = distributions_dir / source_wheel.name
    sdist = distributions_dir / source_sdist.name
    shutil.copyfile(source_wheel, wheel)
    shutil.copyfile(source_sdist, sdist)
    return wheel, sdist


def _create_directory_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except OSError as exc:
        if os.name != "nt":
            pytest.skip(f"directory symlinks unavailable: {exc}")
    command_processor = os.environ.get("COMSPEC", "cmd.exe")
    completed = subprocess.run(
        [command_processor, "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(
            f"directory symlinks and junctions unavailable: {completed.stderr or completed.stdout}"
        )


def _remove_directory_link(link: Path) -> None:
    if link.is_symlink():
        link.unlink()
    elif link.exists():
        os.rmdir(link)


def _write_fake_signature_bundles(root: Path) -> None:
    for artifact in release_artifacts(root):
        cosign_script.bundle_path(artifact).write_bytes(
            f"bundle for {artifact.relative_to(root).as_posix()}\n".encode()
        )


def _write_bound_signing_bundle(
    root: Path,
    *,
    platform: str,
    variant_marker: str | None = None,
    project_root: Path | None = None,
) -> None:
    artifact_project_root = project_root or root
    reports = root / "reports"
    dist = root / "dist"
    reports.mkdir(parents=True)
    dist.mkdir()
    environment = EnvironmentInfo(
        platform=platform,
        python_version="3.14.0",
    )
    candidate_digest = "c" * 64
    evaluation = EvaluationSummary(
        runset_id="candidate",
        runset_digest=candidate_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
        environment=environment,
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="b" * 64,
        candidate_runset_digest=candidate_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.pass_,
        verdict_findings=(() if variant_marker is None else (f"rerun marker {variant_marker}",)),
    )
    evaluation_path = reports / "evaluation-summary.json"
    comparison_path = reports / "comparison-summary.json"
    evaluation_path.write_text(
        json.dumps(evaluation.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    comparison_path.write_text(
        json.dumps(comparison.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    result = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--comparison",
            str(comparison_path),
            "--out",
            str(reports / "evidence-packet.json"),
            "--packet-id",
            "packet-stable",
            "--project-root",
            str(artifact_project_root),
        ],
    )
    assert result.exit_code == 0, result.output
    marker = variant_marker or "stable"
    wheel = dist / "agent_assure-0.6.3-py3-none-any.whl"
    sdist = dist / "agent_assure-0.6.3.tar.gz"
    wheel.write_bytes(f"wheel-{marker}".encode())
    sdist.write_bytes(f"sdist-{marker}".encode())
    compiled = root / "prior-auth.compiled.json"
    fixtures = root / "prior-auth.fixtures.json"
    shutil.copy2(
        ROOT / "tests/golden/compiled_suites/prior_auth_synthetic.compiled.json",
        compiled,
    )
    shutil.copy2(
        ROOT / "tests/golden/compiled_suites/prior_auth_synthetic.fixture-manifest.json",
        fixtures,
    )
    packet_path = reports / "evidence-packet.json"
    manifest_path = reports / "release-artifact-manifest.json"
    packet = load_evidence_packet(packet_path)
    assert packet.release_manifest is not None
    sbom_path = root / "sbom.cdx.json"
    write_sbom(
        build_sbom(
            packet.release_manifest.environment,
            distribution_paths=(wheel, sdist),
            project_root=artifact_project_root,
        ),
        sbom_path,
    )
    manifest = build_release_manifest(
        (
            *packet.release_manifest.artifacts,
            release_artifact(
                "fixture-manifest",
                fixtures,
                project_root=artifact_project_root,
            ),
            release_artifact("sbom", sbom_path, project_root=artifact_project_root),
            release_artifact("python-wheel", wheel, project_root=artifact_project_root),
            release_artifact(
                "source-distribution",
                sdist,
                project_root=artifact_project_root,
            ),
        ),
        environment=packet.release_manifest.environment,
    )
    packet = packet.model_copy(update={"release_manifest": manifest})
    write_release_manifest(manifest, manifest_path)
    write_evidence_packet(packet, packet_path)
    write_evidence_packet_markdown(packet, reports / "evidence-packet.md")
    current_sha = git_output(ROOT, "rev-parse", "HEAD")
    assert current_sha is not None
    replay = build_digest_replay(
        (
            ("compiled-suite", compiled),
            ("fixture-manifest", fixtures),
            ("assurance-evidence-graph", reports / "assurance-evidence-graph.json"),
            ("evidence-packet", packet_path),
            ("release-artifact-manifest", manifest_path),
        ),
        project_root=artifact_project_root,
        source_commit=current_sha,
        source_ref="refs/tags/v0.6.3",
    )
    write_digest_replay(replay, root / "release-digest-replay.json")
    shutil.copy2(ROOT / "docs/release_notes/v0.6.3.md", root / "release-notes.md")


def _stable_review_digests(root: Path) -> tuple[tuple[str, str], ...]:
    reports = root / "reports"
    replay = build_digest_replay(
        (
            ("evaluation-summary", reports / "evaluation-summary.json"),
            ("comparison-summary", reports / "comparison-summary.json"),
            ("assurance-evidence-graph", reports / "assurance-evidence-graph.json"),
            ("evidence-packet", reports / "evidence-packet.json"),
            (
                "release-artifact-manifest",
                reports / "release-artifact-manifest.json",
            ),
        ),
        project_root=root,
        source_commit="1" * 40,
    )
    return tuple((artifact.role, artifact.sha256) for artifact in replay.artifacts)
