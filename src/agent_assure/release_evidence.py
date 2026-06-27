from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from agent_assure.artifact_io import file_sha256, git_output
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
ManifestDigestMode = Literal["raw-sha256", "replay-stable-json-sha256", "not-replayed"]
ROLE_DIGEST_MODES: dict[str, ReplayDigestMode] = {
    "baseline-runset": "raw-sha256",
    "candidate-runset": "raw-sha256",
    "compiled-suite": "raw-sha256",
    "comparison-report": "replay-stable-json-sha256",
    "comparison-summary": "replay-stable-json-sha256",
    "evaluation-report": "replay-stable-json-sha256",
    "evaluation-summary": "replay-stable-json-sha256",
    "evidence-packet": "replay-stable-json-sha256",
    "fixture-manifest": "raw-sha256",
    "release-artifact-manifest": "replay-stable-json-sha256",
}
NON_REPLAYED_ROLE_DIGEST_MODES: dict[str, Literal["not-replayed"]] = {
    "dependency-inventory": "not-replayed",
    "python-distribution": "not-replayed",
    "python-wheel": "not-replayed",
    "sbom": "not-replayed",
    "source-distribution": "not-replayed",
}


@dataclass(frozen=True)
class DigestReplayFinding:
    role: str
    path: str
    expected: str
    actual: str | None
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
        source_commit if source_commit is not None else git_output(root, "rev-parse", "HEAD")
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
    expect_ref: str | None = None,
    require_current_commit: bool = False,
) -> DigestReplayVerification:
    findings: list[DigestReplayFinding] = []
    root = artifact_root.resolve()
    findings.extend(
        _commit_findings(
            replay,
            project_root=root,
            expect_commit=expect_commit,
            expect_ref=expect_ref,
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
                    expected="",
                    actual=None,
                    message=f"required release artifact role is missing: {role}",
                )
            )
    for artifact in replay.artifacts:
        try:
            expected_digest_mode = digest_mode_for_role(artifact.role)
        except ValueError as exc:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected=artifact.sha256,
                    actual=None,
                    message=str(exc),
                )
            )
            continue
        if artifact.digest_mode != expected_digest_mode:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected=artifact.sha256,
                    actual=None,
                    message=(
                        "release artifact digest_mode mismatch: "
                        f"{artifact.path} declares {artifact.digest_mode}, "
                        f"expected {expected_digest_mode}"
                    ),
                )
            )
            continue
        try:
            path = _resolve_replay_path(root, artifact.path)
        except ValueError as exc:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected=artifact.sha256,
                    actual=None,
                    message=f"release artifact path is invalid: {exc}",
                )
            )
            continue
        if not path.exists() or not path.is_file():
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected=artifact.sha256,
                    actual=None,
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
                    expected=artifact.sha256,
                    actual=None,
                    message=f"release artifact could not be replayed: {exc}",
                )
            )
            continue
        if actual != artifact.sha256:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected=artifact.sha256,
                    actual=actual,
                    message=f"release artifact digest mismatch: {artifact.path}",
                )
            )
    return DigestReplayVerification(replay=replay, findings=tuple(findings))


def _replay_artifact(role: str, path: Path, project_root: Path) -> ReleaseReplayArtifact:
    raw_artifact = release_artifact(role, path, project_root=project_root)
    digest_mode = digest_mode_for_role(role)
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
    expect_ref: str | None,
    require_current_commit: bool,
) -> tuple[DigestReplayFinding, ...]:
    findings: list[DigestReplayFinding] = []
    if expect_commit is not None:
        if replay.source_commit is None:
            findings.append(
                DigestReplayFinding(
                    role="source-commit",
                    path="",
                    expected=expect_commit,
                    actual=None,
                    message="release digest replay does not record source_commit",
                )
            )
        elif replay.source_commit != expect_commit:
            findings.append(
                DigestReplayFinding(
                    role="source-commit",
                    path="",
                    expected=expect_commit,
                    actual=replay.source_commit,
                    message=(
                        "release digest replay source_commit mismatch: "
                        f"expected {expect_commit}, got {replay.source_commit}"
                    ),
                )
            )
    if expect_ref is not None:
        if replay.source_ref is None:
            findings.append(
                DigestReplayFinding(
                    role="source-ref",
                    path="",
                    expected=expect_ref,
                    actual=None,
                    message="release digest replay does not record source_ref",
                )
            )
        elif replay.source_ref != expect_ref:
            findings.append(
                DigestReplayFinding(
                    role="source-ref",
                    path="",
                    expected=expect_ref,
                    actual=replay.source_ref,
                    message=(
                        "release digest replay source_ref mismatch: "
                        f"expected {expect_ref}, got {replay.source_ref}"
                    ),
                )
            )
    if not require_current_commit:
        return tuple(findings)
    if replay.source_commit is None:
        findings.append(
            DigestReplayFinding(
                role="source-commit",
                path="",
                expected="",
                actual=None,
                message="release digest replay does not record source_commit",
            )
        )
        return tuple(findings)
    current = git_output(project_root, "rev-parse", "HEAD")
    if current is None:
        findings.append(
            DigestReplayFinding(
                role="source-commit",
                path="",
                expected=replay.source_commit,
                actual=None,
                message="current git commit could not be determined",
            )
        )
        return tuple(findings)
    if current != replay.source_commit:
        findings.append(
            DigestReplayFinding(
                role="source-commit",
                path="",
                expected=replay.source_commit,
                actual=current,
                message=(
                    "current checkout commit mismatch: release digest replay "
                    f"source_commit is {replay.source_commit}, but current checkout is {current}"
                ),
            )
        )
    return tuple(findings)


def digest_mode_for_role(role: str) -> ReplayDigestMode:
    try:
        return ROLE_DIGEST_MODES[role]
    except KeyError as exc:
        if role in NON_REPLAYED_ROLE_DIGEST_MODES:
            raise ValueError(
                f"release artifact role is recorded but not replayed: {role}"
            ) from exc
        known = ", ".join(sorted((*ROLE_DIGEST_MODES, *NON_REPLAYED_ROLE_DIGEST_MODES)))
        raise ValueError(
            f"unknown release artifact role: {role}; expected one of: {known}"
        ) from exc


def manifest_digest_mode_for_role(role: str) -> ManifestDigestMode:
    if role in NON_REPLAYED_ROLE_DIGEST_MODES:
        return NON_REPLAYED_ROLE_DIGEST_MODES[role]
    return digest_mode_for_role(role)


def _digest_for_artifact(
    *,
    role: str,
    path: Path,
    project_root: Path,
    digest_mode: ReplayDigestMode,
) -> str:
    if digest_mode == "raw-sha256":
        return file_sha256(path)
    if digest_mode == "replay-stable-json-sha256":
        return sha256_hexdigest(_stable_json_projection(role, path, project_root))
    raise ValueError(f"unsupported release replay digest mode: {digest_mode}")


def _stable_json_projection(role: str, path: Path, project_root: Path) -> dict[str, object]:
    payload = load_json(path)
    if role == "evidence-packet":
        return _stable_packet_projection(payload)
    if role == "release-artifact-manifest":
        return _stable_manifest_projection(payload, project_root)
    if role in {"evaluation-summary", "comparison-summary"}:
        return _without_keys(payload, {"environment"})
    if role == "evaluation-report":
        return _stable_evaluation_report_projection(payload)
    if role == "comparison-report":
        return _stable_comparison_report_projection(payload)
    return payload


def _stable_packet_projection(payload: dict[str, object]) -> dict[str, object]:
    projected = {
        key: value
        for key, value in payload.items()
        if key not in {"artifact_digests", "environment", "release_manifest"}
    }
    _drop_nested_keys(projected, "evaluation", {"environment"})
    _drop_nested_keys(projected, "comparison", {"environment"})
    return projected


def _stable_evaluation_report_projection(payload: dict[str, object]) -> dict[str, object]:
    projected = _without_keys(payload, {"environment"})
    _drop_nested_keys(projected, "candidate_vs_expectations", {"environment"})
    return projected


def _stable_comparison_report_projection(payload: dict[str, object]) -> dict[str, object]:
    projected = _without_keys(payload, {"environment"})
    _drop_nested_keys(projected, "candidate_vs_expectations", {"environment"})
    _drop_nested_keys(projected, "baseline_vs_expectations", {"environment"})
    _drop_nested_keys(projected, "comparison_summary", {"environment"})
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
    recorded_sha256 = artifact.get("sha256")
    if not isinstance(recorded_sha256, str):
        raise ValueError(
            f"release artifact manifest entry for {role!r} must record sha256"
        )
    projection: dict[str, object] = {"role": role, "path": path}
    resolved_path = _resolve_replay_path(project_root, path)
    actual_raw_digest = file_sha256(resolved_path)
    if recorded_sha256 != actual_raw_digest:
        raise ValueError(
            "release artifact manifest recorded digest mismatch: "
            f"{path} declares {recorded_sha256}, actual raw-sha256 {actual_raw_digest}"
        )
    digest_mode = manifest_digest_mode_for_role(role)
    projection["digest_mode"] = digest_mode
    if digest_mode == "not-replayed":
        projection["sha256"] = recorded_sha256
        return projection
    actual_digest = _digest_for_artifact(
        role=role,
        path=resolved_path,
        project_root=project_root,
        digest_mode=digest_mode,
    )
    projection["sha256"] = actual_digest
    return projection


def _without_keys(payload: dict[str, object], keys: set[str]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key not in keys}


def _drop_nested_keys(payload: dict[str, object], field: str, keys: set[str]) -> None:
    value = payload.get(field)
    if isinstance(value, dict):
        payload[field] = _without_keys(value, keys)


def _resolve_replay_path(root: Path, path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        raise ValueError(f"absolute paths are not allowed: {path}")
    if ".." in candidate.parts:
        raise ValueError(f"parent-directory segments are not allowed: {path}")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"path escapes artifact root: {path}") from exc
    return resolved
