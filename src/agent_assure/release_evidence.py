from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from agent_assure.artifact_io import git_output, write_text_atomic
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import (
    BoundedFileContents,
    load_json_bytes_bounded,
    read_file_bounded_at,
)
from agent_assure.reporting.sbom import MAX_RELEASE_ARTIFACT_BYTES
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.release import (
    ReleaseDigestReplay,
    ReleaseReplayArtifact,
    ReplayDigestMode,
)
from agent_assure.schema.validation import (
    load_json,
    maximum_artifact_json_bytes,
    project_validated_artifact_payload,
    validate_historical_artifact_payload_for_release_replay,
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
    "0.6.4": CORE_RELEASE_ROLES,
    "0.6.5": CORE_RELEASE_ROLES,
    "0.6.6": CORE_RELEASE_ROLES,
}
ManifestDigestMode = Literal["raw-sha256", "replay-stable-json-sha256", "not-replayed"]
ROLE_DIGEST_MODES: dict[str, ReplayDigestMode] = {
    "assurance-evidence-graph": "replay-stable-json-sha256",
    "baseline-corpus-snapshot": "raw-sha256",
    "baseline-evaluation-summary": "replay-stable-json-sha256",
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
    "evidence-sensitivity-html": "raw-sha256",
    "evidence-sensitivity-markdown": "raw-sha256",
    "evidence-sensitivity-protocol": "raw-sha256",
    "evidence-sensitivity-report": "replay-stable-json-sha256",
    "evidence-packet": "replay-stable-json-sha256",
    "fixture-manifest": "raw-sha256",
    "release-artifact-manifest": "replay-stable-json-sha256",
    "statistical-sufficiency-report": "replay-stable-json-sha256",
    "stochastic-evidence-sensitivity-report": "replay-stable-json-sha256",
    "stochastic-baseline-source-runset": "raw-sha256",
    "stochastic-counterfactual-source-runset": "raw-sha256",
    "counterfactual-corpus-snapshot": "raw-sha256",
}
_STABLE_JSON_ROLE_ARTIFACT_KINDS = {
    "assurance-evidence-graph": "assurance-evidence-graph",
    "baseline-evaluation-summary": "evaluation-summary",
    "comparison-report": "comparison-report",
    "comparison-summary": "comparison-summary",
    "control-efficacy-report": "control-efficacy-report",
    "evaluation-report": "evaluation-report",
    "evaluation-summary": "evaluation-summary",
    "evidence-sensitivity-report": "evidence-sensitivity-report",
    "evidence-packet": "evidence-packet",
    "release-artifact-manifest": "release-artifact-manifest",
    "statistical-sufficiency-report": "statistical-sufficiency-report",
    "stochastic-evidence-sensitivity-report": ("stochastic-evidence-sensitivity-report"),
}
_RAW_FILE_ROLES = frozenset(
    {
        "control-efficacy-gate-profile",
        "control-efficacy-onboarding-config",
        "evidence-sensitivity-html",
        "evidence-sensitivity-markdown",
    }
)
_RAW_JSON_ROLE_ARTIFACT_KINDS = {
    "baseline-corpus-snapshot": "rag-sensitivity-corpus-snapshot",
    "baseline-runset": "run-set",
    "candidate-runset": "run-set",
    "compiled-suite": "compiled-suite",
    "counterfactual-corpus-snapshot": "rag-sensitivity-corpus-snapshot",
    "evidence-sensitivity-protocol": "evidence-sensitivity-protocol",
    "fixture-manifest": "fixture-manifest",
    "stochastic-baseline-source-runset": "run-set",
    "stochastic-counterfactual-source-runset": "run-set",
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


@dataclass(frozen=True)
class _ReplayDigestSnapshot:
    """Raw and replay digests derived from one rooted, bounded file snapshot."""

    raw_sha256: str
    replay_sha256: str


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
        artifacts=tuple(
            _replay_artifact(
                role,
                path,
                root,
                replay_schema_version=SCHEMA_VERSION,
            )
            for role, path in artifacts
        ),
    )


def write_digest_replay(replay: ReleaseDigestReplay, path: Path) -> None:
    payload = replay.model_dump(mode="json", warnings="error")
    replay = ReleaseDigestReplay.model_validate(payload)
    validate_loaded_artifact_payload(payload, "release-digest-replay")
    write_text_atomic(
        path,
        json.dumps(replay.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
    )


def load_digest_replay(path: Path) -> ReleaseDigestReplay:
    payload = load_json(path)
    replay_schema_version = payload.get("schema_version")
    _validate_release_replay_input_payload(
        payload,
        "release-digest-replay",
        replay_schema_version=(
            replay_schema_version if isinstance(replay_schema_version, str) else None
        ),
    )
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
    replay_payload = replay.model_dump(mode="json", warnings="error")
    replay = ReleaseDigestReplay.model_validate(replay_payload)
    _validate_release_replay_input_payload(
        replay_payload,
        "release-digest-replay",
        replay_schema_version=replay.schema_version,
    )
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
            _resolve_replay_path(root, artifact.path)
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
        try:
            actual = _digest_for_artifact(
                role=artifact.role,
                path=Path(artifact.path),
                project_root=root,
                digest_mode=artifact.digest_mode,
                replay_schema_version=replay.schema_version,
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


def _replay_artifact(
    role: str,
    path: Path,
    project_root: Path,
    *,
    replay_schema_version: str,
) -> ReleaseReplayArtifact:
    digest_mode = digest_mode_for_role(role)
    artifact_path = _relative_replay_input_path(path, project_root)
    replay_digest = _digest_for_artifact(
        role=role,
        path=Path(artifact_path),
        project_root=project_root,
        digest_mode=digest_mode,
        replay_schema_version=replay_schema_version,
    )
    return ReleaseReplayArtifact(
        artifact_kind="release-replay-artifact",
        role=role,
        path=artifact_path,
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
    replay_schema_version: str,
) -> str:
    return _digest_snapshot_for_artifact(
        role=role,
        path=path,
        project_root=project_root,
        digest_mode=digest_mode,
        replay_schema_version=replay_schema_version,
    ).replay_sha256


def _digest_snapshot_for_artifact(
    *,
    role: str,
    path: Path,
    project_root: Path,
    digest_mode: ReplayDigestMode,
    replay_schema_version: str,
) -> _ReplayDigestSnapshot:
    if digest_mode == "raw-sha256":
        if role in _RAW_FILE_ROLES:
            contents = _read_release_artifact_snapshot(
                role,
                path,
                project_root=project_root,
            )
        else:
            contents, _ = _validated_raw_json_snapshot(
                role,
                path,
                project_root=project_root,
                replay_schema_version=replay_schema_version,
            )
        return _ReplayDigestSnapshot(
            raw_sha256=contents.sha256,
            replay_sha256=contents.sha256,
        )
    if digest_mode == "replay-stable-json-sha256":
        contents, payload = _validated_stable_json_snapshot(
            role,
            path,
            project_root=project_root,
            replay_schema_version=replay_schema_version,
        )
        return _ReplayDigestSnapshot(
            raw_sha256=contents.sha256,
            replay_sha256=sha256_hexdigest(
                _stable_json_projection_from_payload(
                    role,
                    payload,
                    project_root,
                    replay_schema_version=replay_schema_version,
                )
            ),
        )
    raise ValueError(f"unsupported release replay digest mode: {digest_mode}")


def _read_release_artifact_snapshot(
    role: str,
    path: Path,
    *,
    project_root: Path,
) -> BoundedFileContents:
    return read_file_bounded_at(
        project_root,
        _relative_replay_input_path(path, project_root),
        max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
        label=f"release replay artifact {role!r}",
    )


def _validated_raw_json_digest(
    role: str,
    path: Path,
    project_root: Path,
    *,
    replay_schema_version: str,
) -> str:
    contents, _ = _validated_raw_json_snapshot(
        role,
        path,
        project_root=project_root,
        replay_schema_version=replay_schema_version,
    )
    return contents.sha256


def _validated_raw_json_snapshot(
    role: str,
    path: Path,
    *,
    project_root: Path,
    replay_schema_version: str,
) -> tuple[BoundedFileContents, dict[str, object]]:
    try:
        artifact_kind = _RAW_JSON_ROLE_ARTIFACT_KINDS[role]
    except KeyError as exc:
        raise ValueError(f"role has no raw JSON artifact contract: {role}") from exc
    return _validated_replay_json_snapshot(
        path,
        project_root=project_root,
        artifact_kind=artifact_kind,
        replay_schema_version=replay_schema_version,
    )


def _validated_stable_json_snapshot(
    role: str,
    path: Path,
    *,
    project_root: Path,
    replay_schema_version: str,
) -> tuple[BoundedFileContents, dict[str, object]]:
    try:
        artifact_kind = _STABLE_JSON_ROLE_ARTIFACT_KINDS[role]
    except KeyError as exc:
        raise ValueError(f"role has no stable JSON artifact contract: {role}") from exc
    return _validated_replay_json_snapshot(
        path,
        project_root=project_root,
        artifact_kind=artifact_kind,
        replay_schema_version=replay_schema_version,
    )


def _validated_replay_json_snapshot(
    path: Path,
    *,
    project_root: Path,
    artifact_kind: str,
    replay_schema_version: str,
) -> tuple[BoundedFileContents, dict[str, object]]:
    max_bytes = maximum_artifact_json_bytes(artifact_kind)
    label = f"{artifact_kind} artifact JSON"
    contents = read_file_bounded_at(
        project_root,
        _relative_replay_input_path(path, project_root),
        max_bytes=max_bytes,
        label=label,
    )
    payload = load_json_bytes_bounded(
        contents.data,
        max_bytes=max_bytes,
        label=label,
    )
    _validate_release_replay_input_payload(
        payload,
        artifact_kind,
        replay_schema_version=replay_schema_version,
    )
    return contents, payload


def _stable_json_projection(
    role: str,
    path: Path,
    project_root: Path,
    *,
    replay_schema_version: str,
) -> dict[str, object]:
    _, payload = _validated_stable_json_snapshot(
        role,
        path,
        project_root=project_root,
        replay_schema_version=replay_schema_version,
    )
    return _stable_json_projection_from_payload(
        role,
        payload,
        project_root,
        replay_schema_version=replay_schema_version,
    )


def _stable_json_projection_from_payload(
    role: str,
    payload: dict[str, object],
    project_root: Path,
    *,
    replay_schema_version: str,
) -> dict[str, object]:
    if role == "assurance-evidence-graph":
        return _stable_graph_projection(payload)
    if role == "evidence-packet":
        return _stable_packet_projection(payload)
    if role == "release-artifact-manifest":
        return _stable_manifest_projection(
            payload,
            project_root,
            replay_schema_version=replay_schema_version,
        )
    if role in {"baseline-evaluation-summary", "evaluation-summary", "comparison-summary"}:
        return _without_keys(payload, {"environment"})
    if role == "evaluation-report":
        return _stable_evaluation_report_projection(payload)
    if role == "comparison-report":
        return _stable_comparison_report_projection(payload)
    if role == "evidence-sensitivity-report":
        return _stable_sensitivity_projection(payload)
    if role in {
        "statistical-sufficiency-report",
        "stochastic-evidence-sensitivity-report",
    }:
        return _without_keys(payload, {"report_digest"})
    return payload


def _validate_release_replay_input_payload(
    payload: dict[str, object],
    artifact_kind: str,
    *,
    replay_schema_version: str | None,
) -> str:
    """Select assurance validation or historical integrity-only reproduction.

    Historical release replay checks immutable shape only so that an already
    published bundle can reproduce its recorded digest. This result is never an
    assurance-valid result. Current inputs remain on the public semantic
    validator and therefore cannot use this compatibility path as a downgrade.
    """

    schema_version = payload.get("schema_version")
    envelope_version = replay_schema_version
    if envelope_version == SCHEMA_VERSION and schema_version != SCHEMA_VERSION:
        raise ValueError(
            "current release replay requires persisted JSON child "
            f"{artifact_kind!r} to use schema_version {SCHEMA_VERSION!r}; "
            f"received {schema_version!r}"
        )
    if isinstance(schema_version, str) and schema_version != SCHEMA_VERSION:
        return validate_historical_artifact_payload_for_release_replay(payload, artifact_kind)
    return validate_loaded_artifact_payload(payload, artifact_kind)


def _stable_sensitivity_projection(payload: dict[str, object]) -> dict[str, object]:
    """Retain detector semantics while excluding environment-derived identities."""
    projected = _without_keys(payload, {"report_digest"})
    for arm_name in ("baseline_arm", "counterfactual_arm"):
        _drop_nested_keys(
            projected,
            arm_name,
            {"runset_digest", "evaluation_summary_digest"},
        )
    for evaluation_name in ("baseline_evaluation", "counterfactual_evaluation"):
        _drop_nested_keys(projected, evaluation_name, {"environment", "runset_digest"})
    return projected


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
    sensitivity = payload.get("evidence_sensitivity")
    if sensitivity is not None:
        if not isinstance(sensitivity, dict):
            raise ValueError("packet evidence_sensitivity must be an object")
        projected["evidence_sensitivity"] = _stable_sensitivity_projection(sensitivity)
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
    if stable_payload.get("evidence_type") in {
        "evaluation",
        "comparison",
        "evidence_sensitivity",
    }:
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
    *,
    replay_schema_version: str,
) -> dict[str, object]:
    projected = {
        key: value for key, value in payload.items() if key not in {"environment", "manifest_id"}
    }
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("release artifact manifest artifacts must be a list")
    _require_unique_manifest_artifacts(artifacts, project_root=project_root)
    projected["artifacts"] = [
        _stable_manifest_artifact_projection(
            artifact,
            project_root,
            replay_schema_version=replay_schema_version,
        )
        for artifact in artifacts
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
    *,
    replay_schema_version: str,
) -> dict[str, object]:
    if not isinstance(artifact, dict):
        raise ValueError("release artifact manifest entry must be an object")
    role = str(artifact.get("role", ""))
    path = str(artifact.get("path", ""))
    recorded_sha256 = artifact.get("sha256")
    if not isinstance(recorded_sha256, str):
        raise ValueError(f"release artifact manifest entry for {role!r} must record sha256")
    projection: dict[str, object] = {"role": role, "path": path}
    digest_mode = manifest_digest_mode_for_role(role)
    artifact_path = Path(path)
    digest_snapshot: _ReplayDigestSnapshot | None = None
    if digest_mode == "not-replayed":
        actual_raw_digest = _read_release_artifact_snapshot(
            role,
            artifact_path,
            project_root=project_root,
        ).sha256
    else:
        digest_snapshot = _digest_snapshot_for_artifact(
            role=role,
            path=artifact_path,
            project_root=project_root,
            digest_mode=digest_mode,
            replay_schema_version=replay_schema_version,
        )
        actual_raw_digest = digest_snapshot.raw_sha256
    if recorded_sha256 != actual_raw_digest:
        raise ValueError(
            "release artifact manifest recorded digest mismatch: "
            f"{path} declares {recorded_sha256}, actual raw-sha256 {actual_raw_digest}"
        )
    projection["digest_mode"] = digest_mode
    if digest_mode == "not-replayed":
        projection["sha256"] = recorded_sha256
        return projection
    if digest_snapshot is None:  # pragma: no cover - narrowed by digest_mode above
        raise AssertionError("replayed manifest artifact digest was not computed")
    projection["sha256"] = digest_snapshot.replay_sha256
    return projection


def _without_keys(payload: dict[str, object], keys: set[str]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key not in keys}


def _drop_nested_keys(payload: dict[str, object], field: str, keys: set[str]) -> None:
    value = payload.get(field)
    if isinstance(value, dict):
        payload[field] = _without_keys(value, keys)


def _relative_replay_input_path(path: Path, project_root: Path) -> str:
    """Return a lexical root-relative path without following mutable links."""

    if not path.is_absolute():
        return path.as_posix()
    absolute_root = Path(os.path.abspath(project_root))
    absolute_path = Path(os.path.abspath(path))
    try:
        return absolute_path.relative_to(absolute_root).as_posix()
    except ValueError as exc:
        raise ValueError(
            "release artifact paths must stay under project_root: "
            f"{absolute_path} is outside {absolute_root}"
        ) from exc


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
