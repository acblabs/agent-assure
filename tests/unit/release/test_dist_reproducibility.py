from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from assert_dist_reproducible import (  # noqa: E402
    compare_distribution_artifacts,
    compare_release_bundle_artifacts,
    stage_verified_release_bundle,
)
from assert_dist_reproducible import (  # noqa: E402
    main as reproducibility_main,
)

from agent_assure.schema.environment import EnvironmentInfo  # noqa: E402
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest  # noqa: E402


def test_distribution_reproducibility_reports_hash_mismatch() -> None:
    expected = _manifest(
        _artifact("python-wheel", ".tmp/release/dist/agent_assure-0.1.0.whl", "a"),
    )
    actual = _manifest(
        _artifact("python-wheel", ".tmp/release/dist/agent_assure-0.1.0.whl", "b"),
    )

    findings = compare_distribution_artifacts(expected, actual)

    assert len(findings) == 1
    assert findings[0].role == "python-wheel"
    assert findings[0].filename == "agent_assure-0.1.0.whl"
    assert findings[0].expected == "a" * 64
    assert findings[0].actual == "b" * 64
    assert "not byte-reproducible" in findings[0].message


def test_distribution_reproducibility_reports_missing_distribution() -> None:
    expected = _manifest(
        _artifact("source-distribution", ".tmp/release/dist/agent_assure-0.1.0.tar.gz", "a"),
    )
    actual = _manifest()

    findings = compare_distribution_artifacts(expected, actual)

    assert len(findings) == 1
    assert findings[0].role == "source-distribution"
    assert findings[0].actual is None
    assert "missing a published distribution artifact" in findings[0].message


def test_distribution_reproducibility_can_require_distribution_entries() -> None:
    findings = compare_distribution_artifacts(
        _manifest(),
        _manifest(),
        require_distributions=True,
    )

    assert len(findings) == 1
    assert findings[0].role == "distribution"
    assert "contains no distribution artifacts" in findings[0].message


def test_actual_malicious_wheel_fails_even_when_manifest_lies_about_its_digest(
    tmp_path: Path,
) -> None:
    downloaded = tmp_path / "downloaded"
    rebuilt = tmp_path / "rebuilt"
    clean_wheel = b"clean independently rebuilt wheel"
    malicious_wheel = b"parseable but malicious downloaded wheel"
    sdist = b"clean source distribution"
    manifest = _manifest(
        _artifact(
            "python-wheel",
            ".tmp/release/dist/agent_assure-0.1.0-py3-none-any.whl",
            hashlib.sha256(clean_wheel).hexdigest(),
        ),
        _artifact(
            "source-distribution",
            ".tmp/release/dist/agent_assure-0.1.0.tar.gz",
            hashlib.sha256(sdist).hexdigest(),
        ),
    ).model_dump_json(indent=2).encode("utf-8")
    _write_signing_bundle(
        downloaded,
        wheel=malicious_wheel,
        sdist=sdist,
        manifest=manifest,
    )
    _write_signing_bundle(
        rebuilt,
        wheel=clean_wheel,
        sdist=sdist,
        manifest=manifest,
    )

    findings = compare_release_bundle_artifacts(downloaded, rebuilt)

    assert [finding.path for finding in findings] == [
        "dist/agent_assure-0.1.0-py3-none-any.whl"
    ]
    assert findings[0].downloaded_sha256 == hashlib.sha256(malicious_wheel).hexdigest()
    assert findings[0].rebuilt_sha256 == hashlib.sha256(clean_wheel).hexdigest()
    verified = tmp_path / "verified"
    assert (
        reproducibility_main(
            [
                str(downloaded),
                str(rebuilt),
                "--verified-out",
                str(verified),
            ]
        )
        == 1
    )
    assert not verified.exists()


@pytest.mark.parametrize(
    "relative_path",
    (
        "reports/evidence-packet.json",
        "reports/evidence-packet.md",
        "reports/release-artifact-manifest.json",
        "release-digest-replay.json",
        "release-notes.md",
        "sbom.cdx.json",
        "dist/agent_assure-0.1.0-py3-none-any.whl",
        "dist/agent_assure-0.1.0.tar.gz",
    ),
)
def test_every_future_signing_input_is_compared_by_actual_bytes(
    tmp_path: Path,
    relative_path: str,
) -> None:
    downloaded = tmp_path / "downloaded"
    rebuilt = tmp_path / "rebuilt"
    _write_signing_bundle(downloaded, include_release_notes=True)
    _write_signing_bundle(rebuilt, include_release_notes=True)
    with (downloaded / relative_path).open("ab") as handle:
        handle.write(b"tampered")

    findings = compare_release_bundle_artifacts(
        downloaded,
        rebuilt,
        require_release_notes=True,
    )

    assert [finding.path for finding in findings] == [relative_path]


def test_verified_staging_contains_only_independently_rebuilt_signing_inputs(
    tmp_path: Path,
) -> None:
    rebuilt = tmp_path / "rebuilt"
    destination = tmp_path / "verified"
    _write_signing_bundle(rebuilt, include_release_notes=True)
    unrelated = rebuilt / "logs" / "untrusted.log"
    unrelated.parent.mkdir()
    unrelated.write_text("not a signing input\n", encoding="utf-8")

    stage_verified_release_bundle(
        rebuilt,
        destination,
        require_release_notes=True,
    )

    assert not (destination / "logs").exists()
    assert compare_release_bundle_artifacts(
        rebuilt,
        destination,
        require_release_notes=True,
    ) == ()


def test_unsigned_bundle_with_preexisting_signature_sidecar_fails_closed(
    tmp_path: Path,
) -> None:
    downloaded = tmp_path / "downloaded"
    rebuilt = tmp_path / "rebuilt"
    _write_signing_bundle(downloaded)
    _write_signing_bundle(rebuilt)
    (downloaded / "reports" / "evidence-packet.json.bundle").write_text(
        "attacker supplied\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="contains signature sidecar"):
        compare_release_bundle_artifacts(downloaded, rebuilt)


def _artifact(role: str, path: str, digest_char: str) -> ReleaseArtifact:
    digest = digest_char if len(digest_char) == 64 else digest_char * 64
    return ReleaseArtifact(
        artifact_kind="release-artifact",
        role=role,
        path=path,
        sha256=digest,
    )


def _manifest(*artifacts: ReleaseArtifact) -> ReleaseArtifactManifest:
    return ReleaseArtifactManifest(
        artifact_kind="release-artifact-manifest",
        manifest_id="manifest-test",
        artifacts=artifacts,
        environment=EnvironmentInfo(
            artifact_kind="environment-info",
            platform="test",
            python_version="3.14",
        ),
    )


def _write_signing_bundle(
    root: Path,
    *,
    wheel: bytes = b"wheel",
    sdist: bytes = b"sdist",
    manifest: bytes = b"{}\n",
    include_release_notes: bool = False,
) -> None:
    files: dict[str, bytes] = {
        "reports/evidence-packet.json": b"{}\n",
        "reports/evidence-packet.md": b"# Evidence\n",
        "reports/release-artifact-manifest.json": manifest,
        "release-digest-replay.json": b"{}\n",
        "sbom.cdx.json": b"{}\n",
        "dist/agent_assure-0.1.0-py3-none-any.whl": wheel,
        "dist/agent_assure-0.1.0.tar.gz": sdist,
    }
    if include_release_notes:
        files["release-notes.md"] = b"# Release notes\n"
    for relative_path, content in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
