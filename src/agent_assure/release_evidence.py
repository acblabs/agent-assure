from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from agent_assure.artifact_io import file_sha256, git_output, write_text_atomic
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    loads_json_bounded,
    read_bytes_bounded,
)
from agent_assure.reporting.environment import release_artifact
from agent_assure.schema.release import (
    ReleaseDigestReplay,
    ReleaseReplayArtifact,
    ReplayDigestMode,
)
from agent_assure.schema.validation import (
    load_json,
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)

LEGACY_CORE_RELEASE_ROLES = (
    "compiled-suite",
    "fixture-manifest",
    "evidence-packet",
    "release-artifact-manifest",
)
CORE_RELEASE_ROLES = (
    "compiled-suite",
    "fixture-manifest",
    "assurance-evidence-graph",
    "evidence-packet",
    "release-artifact-manifest",
)
_CORE_RELEASE_ROLES_BY_SCHEMA_VERSION: dict[str, tuple[str, ...]] = {
    # Frozen v0.1 replays are projected to v0.2 before this policy is applied.
    "0.2.0": LEGACY_CORE_RELEASE_ROLES,
    "0.3.1": LEGACY_CORE_RELEASE_ROLES,
    "0.4.3": LEGACY_CORE_RELEASE_ROLES,
    "0.5.0": LEGACY_CORE_RELEASE_ROLES,
    "0.6.0": LEGACY_CORE_RELEASE_ROLES,
    "0.6.1": LEGACY_CORE_RELEASE_ROLES,
    "0.6.2": LEGACY_CORE_RELEASE_ROLES,
    "0.6.3": CORE_RELEASE_ROLES,
}
ManifestDigestMode = Literal["raw-sha256", "replay-stable-json-sha256", "not-replayed"]
ROLE_DIGEST_MODES: dict[str, ReplayDigestMode] = {
    "assurance-evidence-graph": "replay-stable-json-sha256",
    "baseline-runset": "raw-sha256",
    "candidate-runset": "raw-sha256",
    "compiled-suite": "raw-sha256",
    "comparison-report": "replay-stable-json-sha256",
    "comparison-summary": "replay-stable-json-sha256",
    "control-efficacy-gate-profile": "raw-sha256",
    "control-efficacy-onboarding-config": "raw-sha256",
    "control-efficacy-report": "replay-stable-json-sha256",
    "evaluation-report": "replay-stable-json-sha256",
    "evaluation-summary": "replay-stable-json-sha256",
    "evidence-packet": "replay-stable-json-sha256",
    "fixture-manifest": "raw-sha256",
    "release-artifact-manifest": "replay-stable-json-sha256",
}
_STABLE_JSON_ROLE_ARTIFACT_KINDS = {
    "assurance-evidence-graph": "assurance-evidence-graph",
    "comparison-report": "comparison-report",
    "comparison-summary": "comparison-summary",
    "control-efficacy-report": "control-efficacy-report",
    "evaluation-report": "evaluation-report",
    "evaluation-summary": "evaluation-summary",
    "evidence-packet": "evidence-packet",
    "release-artifact-manifest": "release-artifact-manifest",
}
_RAW_FILE_ROLES = frozenset(
    {
        "control-efficacy-gate-profile",
        "control-efficacy-onboarding-config",
    }
)
_RAW_JSON_ROLE_ARTIFACT_KINDS = {
    "baseline-runset": "run-set",
    "candidate-runset": "run-set",
    "compiled-suite": "compiled-suite",
    "fixture-manifest": "fixture-manifest",
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


def core_release_roles_for_schema_version(schema_version: str) -> tuple[str, ...]:
    """Return the core release roles authored by a replay schema version."""
    try:
        return _CORE_RELEASE_ROLES_BY_SCHEMA_VERSION[schema_version]
    except KeyError as exc:
        raise ValueError(
            f"no core release-role policy for schema version: {schema_version}"
        ) from exc


def build_digest_replay(
    artifacts: tuple[tuple[str, Path], ...],
    *,
    project_root: Path,
    source_commit: str | None = None,
    source_ref: str | None = None,
) -> ReleaseDigestReplay:
    root = project_root.resolve()
    _require_unique_replay_inputs(artifacts)
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
    write_text_atomic(
        path,
        json.dumps(replay.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
    )


def load_digest_replay(path: Path) -> ReleaseDigestReplay:
    payload = load_validated_artifact_payload(path, "release-digest-replay")
    return project_validated_artifact_payload(
        _runtime_replay_projection(payload),
        ReleaseDigestReplay,
        kind="release-digest-replay",
    )


def _runtime_replay_projection(payload: dict[str, object]) -> dict[str, object]:
    """Project the shape-identical v0.1 replay contract into the typed v0.2 model."""
    if payload.get("schema_version") != "0.1.0":
        return payload
    projected = dict(payload)
    projected["schema_version"] = "0.2.0"
    artifacts = projected.get("artifacts")
    if isinstance(artifacts, list):
        projected["artifacts"] = [
            ({**artifact, "schema_version": "0.2.0"} if isinstance(artifact, dict) else artifact)
            for artifact in artifacts
        ]
    return projected


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
    findings.extend(_artifact_identity_findings(replay.artifacts, artifact_root=root))
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
    digest_mode = digest_mode_for_role(role)
    replay_digest = _digest_for_artifact(
        role=role,
        path=path,
        project_root=project_root,
        digest_mode=digest_mode,
    )
    raw_artifact = release_artifact(role, path, project_root=project_root)
    return ReleaseReplayArtifact(
        artifact_kind="release-replay-artifact",
        role=raw_artifact.role,
        path=raw_artifact.path,
        sha256=replay_digest,
        digest_mode=digest_mode,
    )


def _artifacts_by_role(
    artifacts: tuple[ReleaseReplayArtifact, ...],
) -> dict[str, ReleaseReplayArtifact]:
    by_role: dict[str, ReleaseReplayArtifact] = {}
    for artifact in artifacts:
        by_role.setdefault(artifact.role, artifact)
    return by_role


def _require_unique_replay_inputs(artifacts: tuple[tuple[str, Path], ...]) -> None:
    seen_roles: set[str] = set()
    seen_paths: list[tuple[Path, Path]] = []
    for role, path in artifacts:
        resolved = path.resolve()
        if role in seen_roles:
            raise ValueError(f"duplicate release replay role: {role}")
        if any(
            resolved == prior_resolved or _same_file(path, prior_path)
            for prior_path, prior_resolved in seen_paths
        ):
            raise ValueError(f"duplicate release replay path: {path}")
        seen_roles.add(role)
        seen_paths.append((path, resolved))


def _artifact_identity_findings(
    artifacts: tuple[ReleaseReplayArtifact, ...],
    *,
    artifact_root: Path,
) -> tuple[DigestReplayFinding, ...]:
    findings: list[DigestReplayFinding] = []
    seen_roles: set[str] = set()
    seen_paths: set[str] = set()
    seen_resolved_paths: list[tuple[str, Path]] = []
    for artifact in artifacts:
        if artifact.role in seen_roles:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected="unique",
                    actual=artifact.role,
                    message=f"duplicate release replay role: {artifact.role}",
                )
            )
        if artifact.path in seen_paths:
            findings.append(
                DigestReplayFinding(
                    role=artifact.role,
                    path=artifact.path,
                    expected="unique",
                    actual=artifact.path,
                    message=f"duplicate release replay path: {artifact.path}",
                )
            )
        else:
            try:
                resolved_path = _resolve_replay_path(artifact_root, artifact.path)
            except ValueError:
                resolved_path = None
            if resolved_path is not None:
                aliased_path = next(
                    (
                        prior_path
                        for prior_path, prior_resolved in seen_resolved_paths
                        if resolved_path == prior_resolved
                        or _same_file(resolved_path, prior_resolved)
                    ),
                    None,
                )
                if aliased_path is not None:
                    findings.append(
                        DigestReplayFinding(
                            role=artifact.role,
                            path=artifact.path,
                            expected="unique",
                            actual=aliased_path,
                            message=(
                                "duplicate release replay path alias: "
                                f"{artifact.path} aliases {aliased_path}"
                            ),
                        )
                    )
                else:
                    seen_resolved_paths.append((artifact.path, resolved_path))
        seen_roles.add(artifact.role)
        seen_paths.add(artifact.path)
    return tuple(findings)


def _same_file(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except OSError:
        return False


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
            raise ValueError(f"release artifact role is recorded but not replayed: {role}") from exc
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
        if role in _RAW_FILE_ROLES:
            return file_sha256(path)
        return _validated_raw_json_digest(role, path)
    if digest_mode == "replay-stable-json-sha256":
        return sha256_hexdigest(_stable_json_projection(role, path, project_root))
    raise ValueError(f"unsupported release replay digest mode: {digest_mode}")


def _validated_raw_json_digest(role: str, path: Path) -> str:
    try:
        artifact_kind = _RAW_JSON_ROLE_ARTIFACT_KINDS[role]
    except KeyError as exc:
        raise ValueError(f"role has no raw JSON artifact contract: {role}") from exc
    raw = read_bytes_bounded(
        path,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=f"{artifact_kind} artifact JSON",
    )
    payload = loads_json_bounded(
        raw.decode("utf-8"),
        label=f"{artifact_kind} artifact JSON",
    )
    if not isinstance(payload, dict):
        raise ValueError(f"{artifact_kind} artifact JSON root must be an object")
    validate_loaded_artifact_payload(payload, artifact_kind)
    return hashlib.sha256(raw).hexdigest()


def _stable_json_projection(role: str, path: Path, project_root: Path) -> dict[str, object]:
    payload = load_json(path)
    try:
        artifact_kind = _STABLE_JSON_ROLE_ARTIFACT_KINDS[role]
    except KeyError as exc:
        raise ValueError(f"role has no stable JSON artifact contract: {role}") from exc
    validate_loaded_artifact_payload(payload, artifact_kind)
    if role == "assurance-evidence-graph":
        return _stable_graph_projection(payload)
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
    if projected.pop("evidence_graph_digest", None) is not None:
        projected["evidence_graph_binding"] = True
    _drop_nested_keys(projected, "evaluation", {"environment"})
    _drop_nested_keys(projected, "comparison", {"environment"})
    return projected


def _stable_graph_projection(payload: dict[str, object]) -> dict[str, object]:
    """Retain graph semantics while excluding volatile, derived digest values."""
    projected = _without_keys(payload, {"graph_digest"})
    nodes = payload.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("assurance evidence graph nodes must be a list")
    projected["nodes"] = [_stable_graph_node_projection(node) for node in nodes]
    return projected


def _stable_graph_node_projection(node: object) -> dict[str, object]:
    if not isinstance(node, dict):
        raise ValueError("assurance evidence graph node must be an object")
    projected = _without_keys(node, {"payload_digest"})
    payload = node.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("assurance evidence graph node payload must be an object")
    stable_payload = dict(payload)
    if stable_payload.get("evidence_type") in {"evaluation", "comparison"}:
        stable_payload.pop("source_digest", None)
    projected["payload"] = stable_payload
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
    _require_unique_manifest_artifacts(artifacts, project_root=project_root)
    projected["artifacts"] = [
        _stable_manifest_artifact_projection(artifact, project_root) for artifact in artifacts
    ]
    return projected


def _require_unique_manifest_artifacts(
    artifacts: list[object],
    *,
    project_root: Path,
) -> None:
    seen_roles: set[str] = set()
    seen_paths: set[str] = set()
    seen_resolved_paths: list[tuple[str, Path]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("release artifact manifest entry must be an object")
        role = artifact.get("role")
        path = artifact.get("path")
        if not isinstance(role, str) or not isinstance(path, str):
            raise ValueError("release artifact manifest entries require string role and path")
        if role in seen_roles:
            raise ValueError(f"duplicate release artifact manifest role: {role}")
        if path in seen_paths:
            raise ValueError(f"duplicate release artifact manifest path: {path}")
        resolved_path = _resolve_replay_path(project_root, path)
        aliased_path = next(
            (
                prior_path
                for prior_path, prior_resolved in seen_resolved_paths
                if resolved_path == prior_resolved or _same_file(resolved_path, prior_resolved)
            ),
            None,
        )
        if aliased_path is not None:
            raise ValueError(
                f"duplicate release artifact manifest path alias: {path} aliases {aliased_path}"
            )
        seen_roles.add(role)
        seen_paths.add(path)
        seen_resolved_paths.append((path, resolved_path))


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
        raise ValueError(f"release artifact manifest entry for {role!r} must record sha256")
    projection: dict[str, object] = {"role": role, "path": path}
    resolved_path = _resolve_replay_path(project_root, path)
    digest_mode = manifest_digest_mode_for_role(role)
    actual_digest = None
    if digest_mode == "raw-sha256":
        actual_digest = _digest_for_artifact(
            role=role,
            path=resolved_path,
            project_root=project_root,
            digest_mode=digest_mode,
        )
        actual_raw_digest = actual_digest
    else:
        actual_raw_digest = file_sha256(resolved_path)
    if recorded_sha256 != actual_raw_digest:
        raise ValueError(
            "release artifact manifest recorded digest mismatch: "
            f"{path} declares {recorded_sha256}, actual raw-sha256 {actual_raw_digest}"
        )
    projection["digest_mode"] = digest_mode
    if digest_mode == "not-replayed":
        projection["sha256"] = recorded_sha256
        return projection
    if actual_digest is None:
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
