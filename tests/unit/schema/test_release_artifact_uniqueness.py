from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.release import (
    ReleaseArtifact,
    ReleaseArtifactManifest,
    ReleaseDigestReplay,
    ReleaseReplayArtifact,
)


@pytest.mark.parametrize("duplicate_field", ["role", "path"])
def test_release_manifest_rejects_ambiguous_artifact_identity(
    duplicate_field: str,
) -> None:
    first = _manifest_artifact("python-wheel", "dist/first.whl", "a")
    second = _manifest_artifact("source-distribution", "dist/second.tar.gz", "b")
    second_payload = second.model_dump(mode="json")
    second_payload[duplicate_field] = getattr(first, duplicate_field)

    with pytest.raises(ValidationError, match=f"duplicate artifact {duplicate_field}"):
        ReleaseArtifactManifest(
            artifact_kind="release-artifact-manifest",
            manifest_id="manifest-test",
            artifacts=(first, second_payload),
            environment=EnvironmentInfo(
                artifact_kind="environment-info",
                platform="test",
                python_version="3.14",
            ),
        )


@pytest.mark.parametrize("duplicate_field", ["role", "path"])
def test_release_replay_rejects_ambiguous_artifact_identity(
    duplicate_field: str,
) -> None:
    first = _replay_artifact("compiled-suite", "suite.json", "a")
    second = _replay_artifact("fixture-manifest", "fixtures.json", "b")
    second_payload = second.model_dump(mode="json")
    second_payload[duplicate_field] = getattr(first, duplicate_field)

    with pytest.raises(ValidationError, match=f"duplicate artifact {duplicate_field}"):
        ReleaseDigestReplay(
            artifact_kind="release-digest-replay",
            source_commit="a" * 40,
            artifacts=(first, second_payload),
        )


def _manifest_artifact(role: str, path: str, digest: str) -> ReleaseArtifact:
    return ReleaseArtifact(
        artifact_kind="release-artifact",
        role=role,
        path=path,
        sha256=digest * 64,
    )


def _replay_artifact(role: str, path: str, digest: str) -> ReleaseReplayArtifact:
    return ReleaseReplayArtifact(
        artifact_kind="release-replay-artifact",
        role=role,
        path=path,
        sha256=digest * 64,
        digest_mode="raw-sha256",
    )
