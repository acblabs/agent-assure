from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.reporting.environment import release_artifact
from agent_assure.schema.release import (
    ReleaseDigestReplay,
    ReleaseReplayArtifact,
    ReplayDigestMode,
)
from agent_assure.schema.validation import load_json

CORE_RELEASE_ROLES = (
    "compiled-suite",
    "fixture-manifest",
    "evidence-packet",
    "release-artifact-manifest",
)
STABLE_JSON_REPLAY_ROLES = frozenset({"evidence-packet", "release-artifact-manifest"})
SUMMARY_REPLAY_ROLES = frozenset({"evaluation-summary", "comparison-summary"})
NON_REPLAYED_MANIFEST_ROLES = frozenset({"dependency-inventory"})


@dataclass(frozen=True)
class DigestReplayFinding:
    role: str
    path: str
    expected_sha256: str
    actual_sha256: str | None
    message: str


@dataclass(frozen=True)
class DigestReplayVerification:
    replay: ReleaseDigestReplay
    findings: tuple[DigestReplayFinding, ...]

    @property
    def ok(self) -> bool:
        return not self.findings


def build_digest_replay(
    artifacts: tuple[tuple[str, Path], ...],
    *,
    project_root: Path,
    source_commit: str | None = None,
    source_ref: str | None = None,
) -> ReleaseDigestReplay:
    root = project_root.resolve()
    resolved_commit = (
        source_commit if source_commit is not None else _git_output(root, "rev-parse", "HEAD")
    )
    return ReleaseDigestReplay(
        artifact_kind="release-digest-replay",
        source_commit=resolved_commit,
        source_ref=source_ref,
        artifacts=tuple(_replay_artifact(role, path, root) for role, path in artifacts),
    )


def write_digest_replay(replay: ReleaseDigestReplay, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(replay.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def load_digest_replay(path: Path) -> ReleaseDigestReplay:
    return ReleaseDigestReplay.model_validate(load_json(path))


def verify_digest_replay(
    replay: ReleaseDigestReplay,
    *,
    artifact_root: Path,
    required_roles: tuple[str, ...] = (),
    expect_commit: str | None = None,
    require_current_commit: bool = False,
) -> DigestReplayVerification:
    findings: list[DigestReplayFinding] = []
    root = artifact_root.resolve()
    findings.extend(
        _commit_findings(
            replay,
            project_root=root,
            expect_commit=expect_commit,
            require_current_commit=require_current_commit,
        )
    )
    artifacts_by_role = _artifacts_by_role(replay.artifacts)
    for role in required_roles:
        if role not in artifacts_by_role:
            findings.append(
                DigestReplayFinding(
                    role=role,
                    path="",
                    expected_sha256="",
                    actual_sha256=None,
                    message=f"required release artifact role is missing: {role}",
                )
            )
    for artifact in replay.artifacts:
        expected_digest_mode = _default_digest_mode(artifact.role)
        if artifact.digest_mode != expected_digest_mode:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected_sha256=artifact.sha256,
                    actual_sha256=None,
                    message=(
                        "release artifact digest_mode mismatch: "
                        f"{artifact.path} declares {artifact.digest_mode}, "
                        f"expected {expected_digest_mode}"
                    ),
                )
            )
            continue
        path = _resolve_replay_path(root, artifact.path)
        if not path.exists() or not path.is_file():
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected_sha256=artifact.sha256,
                    actual_sha256=None,
                    message=f"release artifact is missing: {artifact.path}",
                )
            )
            continue
        try:
            actual = _digest_for_artifact(
                role=artifact.role,
                path=path,
                project_root=root,
                digest_mode=artifact.digest_mode,
            )
        except (OSError, ValueError) as exc:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected_sha256=artifact.sha256,
                    actual_sha256=None,
                    message=f"release artifact could not be replayed: {exc}",
                )
            )
            continue
        if actual != artifact.sha256:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected_sha256=artifact.sha256,
                    actual_sha256=actual,
                    message=f"release artifact digest mismatch: {artifact.path}",
                )
            )
    return DigestReplayVerification(replay=replay, findings=tuple(findings))


def _replay_artifact(role: str, path: Path, project_root: Path) -> ReleaseReplayArtifact:
    raw_artifact = release_artifact(role, path, project_root=project_root)
    digest_mode = _default_digest_mode(role)
    return ReleaseReplayArtifact(
        artifact_kind="release-replay-artifact",
        role=raw_artifact.role,
        path=raw_artifact.path,
        sha256=_digest_for_artifact(
            role=role,
            path=path,
            project_root=project_root,
            digest_mode=digest_mode,
        ),
        digest_mode=digest_mode,
    )


def _artifacts_by_role(
    artifacts: tuple[ReleaseReplayArtifact, ...],
) -> dict[str, ReleaseReplayArtifact]:
    by_role: dict[str, ReleaseReplayArtifact] = {}
    for artifact in artifacts:
        # First-wins is only a presence index; every listed artifact is still
        # verified in order below.
        by_role.setdefault(artifact.role, artifact)
    return by_role


def _commit_findings(
    replay: ReleaseDigestReplay,
    *,
    project_root: Path,
    expect_commit: str | None,
    require_current_commit: bool,
) -> tuple[DigestReplayFinding, ...]:
    expected = expect_commit or (replay.source_commit if require_current_commit else None)
    if expected is None:
        if require_current_commit:
            return (
                DigestReplayFinding(
                    role="source-commit",
                    path="",
                    expected_sha256="",
                    actual_sha256=None,
                    message="release digest replay does not record source_commit",
                ),
            )
        return ()
    current = _git_output(project_root, "rev-parse", "HEAD")
    if current is None:
        return (
            DigestReplayFinding(
                role="source-commit",
                path="",
                expected_sha256="",
                actual_sha256=None,
                message="current git commit could not be determined",
            ),
        )
    if current != expected:
        return (
            DigestReplayFinding(
                role="source-commit",
                path="",
                expected_sha256="",
                actual_sha256=current,
                message=(
                    "release digest replay was produced from commit "
                    f"{expected}, but current checkout is {current}"
                ),
            ),
        )
    return ()


def _default_digest_mode(role: str) -> ReplayDigestMode:
    if role in STABLE_JSON_REPLAY_ROLES:
        return "replay-stable-json-sha256"
    return "raw-sha256"


def _digest_for_artifact(
    *,
    role: str,
    path: Path,
    project_root: Path,
    digest_mode: ReplayDigestMode,
) -> str:
    if digest_mode == "raw-sha256":
        return _file_sha256(path)
    if digest_mode == "replay-stable-json-sha256":
        return sha256_hexdigest(_stable_json_projection(role, path, project_root))
    raise ValueError(f"unsupported release replay digest mode: {digest_mode}")


def _stable_json_projection(role: str, path: Path, project_root: Path) -> dict[str, object]:
    payload = load_json(path)
    if role == "evidence-packet":
        return _stable_packet_projection(payload)
    if role == "release-artifact-manifest":
        return _stable_manifest_projection(payload, project_root)
    if role in SUMMARY_REPLAY_ROLES:
        return _without_environment(payload)
    return payload


def _stable_packet_projection(payload: dict[str, object]) -> dict[str, object]:
    projected = {
        key: value
        for key, value in payload.items()
        if key not in {"artifact_digests", "environment", "release_manifest"}
    }
    evaluation = projected.get("evaluation")
    if isinstance(evaluation, dict):
        projected["evaluation"] = _without_environment(evaluation)
    comparison = projected.get("comparison")
    if isinstance(comparison, dict):
        projected["comparison"] = _without_environment(comparison)
    return projected


def _stable_manifest_projection(
    payload: dict[str, object],
    project_root: Path,
) -> dict[str, object]:
    projected = {
        key: value for key, value in payload.items() if key not in {"environment", "manifest_id"}
    }
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("release artifact manifest artifacts must be a list")
    projected["artifacts"] = [
        _stable_manifest_artifact_projection(artifact, project_root) for artifact in artifacts
    ]
    return projected


def _stable_manifest_artifact_projection(
    artifact: object,
    project_root: Path,
) -> dict[str, object]:
    if not isinstance(artifact, dict):
        raise ValueError("release artifact manifest entry must be an object")
    role = str(artifact.get("role", ""))
    path = str(artifact.get("path", ""))
    projection: dict[str, object] = {"role": role, "path": path}
    if role in NON_REPLAYED_MANIFEST_ROLES:
        projection["digest_mode"] = "not-replayed"
        return projection
    digest_mode: ReplayDigestMode = (
        "replay-stable-json-sha256" if role in SUMMARY_REPLAY_ROLES else "raw-sha256"
    )
    projection["digest_mode"] = digest_mode
    projection["sha256"] = _digest_for_artifact(
        role=role,
        path=_resolve_replay_path(project_root, path),
        project_root=project_root,
        digest_mode=digest_mode,
    )
    return projection


def _without_environment(payload: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key != "environment"}


def _resolve_replay_path(root: Path, path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return root / candidate


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_output(project_root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None
