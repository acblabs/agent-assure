from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from assert_dist_reproducible import compare_distribution_artifacts  # noqa: E402

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


def _artifact(role: str, path: str, digest_char: str) -> ReleaseArtifact:
    return ReleaseArtifact(
        artifact_kind="release-artifact",
        role=role,
        path=path,
        sha256=digest_char * 64,
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
