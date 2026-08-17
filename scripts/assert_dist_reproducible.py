from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for import_path in (ROOT, SRC):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from agent_assure.io_limits import read_file_bounded_at  # noqa: E402
from agent_assure.release_evidence import load_digest_replay  # noqa: E402
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest  # noqa: E402
from agent_assure.schema.validation import (  # noqa: E402
    load_validated_artifact_payload,
    project_validated_artifact_payload,
)
from scripts.cosign_release_artifacts import release_artifacts  # noqa: E402

DIST_ROLES = frozenset({"python-distribution", "python-wheel", "source-distribution"})
MAX_VERIFICATION_SUPPORT_BYTES = 128 * 1024 * 1024
_BACKSLASH = "\\"


@dataclass(frozen=True)
class DistributionReproducibilityFinding:
    role: str
    filename: str
    expected: str | None
    actual: str | None
    message: str


@dataclass(frozen=True)
class ReleaseBundleReproducibilityFinding:
    path: str
    downloaded_sha256: str | None
    rebuilt_sha256: str | None
    message: str


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare the actual bytes of every downloaded and independently rebuilt "
            "release blob that is eligible for signing."
        )
    )
    parser.add_argument("downloaded_bundle", type=Path)
    parser.add_argument("rebuilt_bundle", type=Path)
    parser.add_argument(
        "--require-release-notes",
        action="store_true",
        help="Require release-notes.md in both bundles.",
    )
    parser.add_argument(
        "--verified-out",
        type=Path,
        help=(
            "After a successful comparison, copy independently rebuilt signable "
            "blobs plus digest-checked data files required for manifest/replay "
            "verification into this new directory."
        ),
    )
    args = parser.parse_args(argv)

    try:
        downloaded = _release_bundle_index(
            args.downloaded_bundle,
            require_release_notes=args.require_release_notes,
        )
        rebuilt = _release_bundle_index(
            args.rebuilt_bundle,
            require_release_notes=args.require_release_notes,
        )
        findings = _compare_release_bundle_indexes(downloaded, rebuilt)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"release bundle reproducibility check failed closed: {exc}", file=sys.stderr)
        return 1
    if findings:
        print(
            json.dumps(
                {
                    "artifact_kind": "release-bundle-reproducibility-check",
                    "exit_code": 1,
                    "findings": [
                        {
                            "path": finding.path,
                            "downloaded_sha256": finding.downloaded_sha256,
                            "rebuilt_sha256": finding.rebuilt_sha256,
                            "message": finding.message,
                        }
                        for finding in findings
                    ],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    if args.verified_out is not None:
        try:
            stage_verified_release_bundle(
                args.rebuilt_bundle,
                args.verified_out,
                require_release_notes=args.require_release_notes,
                expected_sha256=downloaded,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"verified release bundle staging failed closed: {exc}", file=sys.stderr)
            return 1
    print(f"release signing inputs byte-reproducible: {len(rebuilt)} artifacts")
    return 0


def compare_release_bundle_artifacts(
    downloaded_bundle: Path,
    rebuilt_bundle: Path,
    *,
    require_release_notes: bool = False,
) -> tuple[ReleaseBundleReproducibilityFinding, ...]:
    """Compare actual signable blob bytes without trusting either manifest."""

    downloaded = _release_bundle_index(
        downloaded_bundle,
        require_release_notes=require_release_notes,
    )
    rebuilt = _release_bundle_index(
        rebuilt_bundle,
        require_release_notes=require_release_notes,
    )
    return _compare_release_bundle_indexes(downloaded, rebuilt)


def _compare_release_bundle_indexes(
    downloaded: Mapping[str, str],
    rebuilt: Mapping[str, str],
) -> tuple[ReleaseBundleReproducibilityFinding, ...]:
    findings: list[ReleaseBundleReproducibilityFinding] = []
    for relative_path in sorted(set(downloaded) | set(rebuilt)):
        downloaded_digest = downloaded.get(relative_path)
        rebuilt_digest = rebuilt.get(relative_path)
        if downloaded_digest is None:
            message = "downloaded bundle is missing an independently rebuilt signing input"
        elif rebuilt_digest is None:
            message = "downloaded bundle contains a signing input absent from the rebuild"
        elif downloaded_digest != rebuilt_digest:
            message = "downloaded signing input bytes differ from the independent rebuild"
        else:
            continue
        findings.append(
            ReleaseBundleReproducibilityFinding(
                path=relative_path,
                downloaded_sha256=downloaded_digest,
                rebuilt_sha256=rebuilt_digest,
                message=message,
            )
        )
    return tuple(findings)


def stage_verified_release_bundle(
    rebuilt_bundle: Path,
    destination: Path,
    *,
    require_release_notes: bool = False,
    expected_sha256: Mapping[str, str] | None = None,
) -> None:
    """Stage rebuilt signing inputs and their data-only verification support."""

    source_root = rebuilt_bundle.resolve()
    destination_root = destination.resolve(strict=False)
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"verified output already exists: {destination}")
    if destination_root == source_root or destination_root.is_relative_to(source_root):
        raise ValueError("verified output must not be inside the rebuilt bundle")

    source = _release_bundle_index(
        rebuilt_bundle,
        require_release_notes=require_release_notes,
    )
    expected = dict(expected_sha256) if expected_sha256 is not None else source
    if source != expected:
        raise RuntimeError("rebuilt signing inputs changed after byte comparison")
    support = _verification_support_index(
        rebuilt_bundle,
        signable_paths=frozenset(source),
    )
    destination.mkdir(parents=True)
    for relative_path in sorted({*source, *support}):
        source_path = rebuilt_bundle / Path(relative_path)
        destination_path = destination / Path(relative_path)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination_path)

    staged = _release_bundle_index(
        destination,
        require_release_notes=require_release_notes,
    )
    if staged != expected:
        raise RuntimeError("staged signing inputs changed while they were copied")
    staged_support = {
        relative_path: read_file_bounded_at(
            destination,
            relative_path,
            max_bytes=MAX_VERIFICATION_SUPPORT_BYTES,
            label=f"staged verification support {relative_path}",
        ).sha256
        for relative_path in support
    }
    if staged_support != support:
        raise RuntimeError("staged verification support changed while it was copied")


def _verification_support_index(
    rebuilt_bundle: Path,
    *,
    signable_paths: frozenset[str],
) -> dict[str, str]:
    manifest_path = rebuilt_bundle / "reports" / "release-artifact-manifest.json"
    manifest = project_validated_artifact_payload(
        load_validated_artifact_payload(
            manifest_path,
            "release-artifact-manifest",
        ),
        ReleaseArtifactManifest,
        kind="release-artifact-manifest",
    )
    replay = load_digest_replay(rebuilt_bundle / "release-digest-replay.json")
    artifact_root = _release_artifact_root(
        manifest,
        rebuilt_bundle=rebuilt_bundle,
    )
    support: dict[str, str] = {}
    for artifact in manifest.artifacts:
        relative_path, actual_sha256 = _verified_bundle_artifact(
            artifact_root,
            artifact.path,
            rebuilt_bundle=rebuilt_bundle,
            label=f"release manifest artifact {artifact.role}",
        )
        if actual_sha256 != artifact.sha256:
            raise ValueError(
                "release manifest artifact digest mismatch before staging: "
                f"{artifact.role} ({artifact.path})"
            )
        if relative_path not in signable_paths:
            _record_support_digest(
                support,
                relative_path=relative_path,
                sha256=actual_sha256,
            )
    for replay_artifact in replay.artifacts:
        relative_path, actual_sha256 = _verified_bundle_artifact(
            artifact_root,
            replay_artifact.path,
            rebuilt_bundle=rebuilt_bundle,
            label=f"release replay artifact {replay_artifact.role}",
        )
        if replay_artifact.digest_mode == "raw-sha256":
            if actual_sha256 != replay_artifact.sha256:
                raise ValueError(
                    "raw release replay artifact digest mismatch before staging: "
                    f"{replay_artifact.role} ({replay_artifact.path})"
                )
        elif relative_path not in signable_paths:
            raise ValueError(
                "stable-projection replay support must also be a signable artifact: "
                f"{replay_artifact.role} ({replay_artifact.path})"
            )
        if relative_path not in signable_paths:
            _record_support_digest(
                support,
                relative_path=relative_path,
                sha256=actual_sha256,
            )
    return support


def _release_artifact_root(
    manifest: ReleaseArtifactManifest,
    *,
    rebuilt_bundle: Path,
) -> Path:
    graph_artifact = next(
        (
            artifact
            for artifact in manifest.artifacts
            if artifact.role == "assurance-evidence-graph"
        ),
        None,
    )
    if graph_artifact is None:
        raise ValueError("release manifest has no assurance evidence graph artifact")
    graph_path = _normalized_relative_path(
        graph_artifact.path,
        label="release manifest assurance evidence graph",
    )
    expected_graph = (rebuilt_bundle / "reports" / "assurance-evidence-graph.json").resolve(
        strict=True
    )
    candidate_root = expected_graph
    for expected_part in reversed(graph_path.parts):
        if candidate_root.name != expected_part:
            raise ValueError(
                "release manifest assurance evidence graph does not identify the rebuilt bundle"
            )
        candidate_root = candidate_root.parent
    return candidate_root


def _verified_bundle_artifact(
    artifact_root: Path,
    artifact_path: str,
    *,
    rebuilt_bundle: Path,
    label: str,
) -> tuple[str, str]:
    relative_to_root = _normalized_relative_path(artifact_path, label=label)
    contents = read_file_bounded_at(
        artifact_root,
        relative_to_root,
        max_bytes=MAX_VERIFICATION_SUPPORT_BYTES,
        label=label,
    )
    source_path = (artifact_root / relative_to_root).resolve(strict=True)
    resolved_bundle = rebuilt_bundle.resolve(strict=True)
    try:
        relative_to_bundle = source_path.relative_to(resolved_bundle)
    except ValueError as exc:
        raise ValueError(f"{label} is outside the rebuilt release bundle") from exc
    return relative_to_bundle.as_posix(), contents.sha256


def _normalized_relative_path(value: str, *, label: str) -> Path:
    path = Path(value)
    if (
        path.is_absolute()
        or not path.parts
        or _BACKSLASH in value
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} path is not normalized and confined")
    return path


def _record_support_digest(
    support: dict[str, str],
    *,
    relative_path: str,
    sha256: str,
) -> None:
    prior = support.setdefault(relative_path, sha256)
    if prior != sha256:
        raise ValueError(f"verification support has conflicting digests for {relative_path}")


def _release_bundle_index(
    release_dir: Path,
    *,
    require_release_notes: bool,
) -> dict[str, str]:
    if release_dir.is_symlink() or not release_dir.is_dir():
        raise ValueError(f"release bundle is not a regular directory: {release_dir}")
    artifacts = release_artifacts(release_dir)
    indexed: dict[str, str] = {}
    for artifact in artifacts:
        _require_no_symlink_parent(artifact, root=release_dir)
        relative_path = artifact.relative_to(release_dir).as_posix()
        if relative_path in indexed:
            raise ValueError(f"duplicate release signing input: {relative_path}")
        sidecar = artifact.with_name(f"{artifact.name}.bundle")
        if sidecar.exists() or sidecar.is_symlink():
            raise ValueError(f"unsigned release bundle contains signature sidecar: {sidecar}")
        indexed[relative_path] = _sha256_file(artifact)
    if require_release_notes and "release-notes.md" not in indexed:
        raise ValueError("release bundle is missing required release-notes.md")
    return indexed


def _require_no_symlink_parent(path: Path, *, root: Path) -> None:
    parent = path.parent
    while parent != root:
        if parent.is_symlink():
            raise ValueError(f"release signing input has a symlink parent: {path}")
        next_parent = parent.parent
        if next_parent == parent:
            raise ValueError(f"release signing input escaped its bundle root: {path}")
        parent = next_parent


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compare_distribution_artifacts(
    expected: ReleaseArtifactManifest,
    actual: ReleaseArtifactManifest,
    *,
    require_distributions: bool = False,
) -> tuple[DistributionReproducibilityFinding, ...]:
    """Compare manifest metadata only; this is not a release signing gate."""

    expected_artifacts = _distribution_index(expected)
    actual_artifacts = _distribution_index(actual)
    findings: list[DistributionReproducibilityFinding] = []
    if require_distributions and not expected_artifacts:
        findings.append(
            DistributionReproducibilityFinding(
                role="distribution",
                filename="",
                expected="present",
                actual=None,
                message="expected release manifest contains no distribution artifacts",
            )
        )
    for key in sorted(set(expected_artifacts) | set(actual_artifacts)):
        role, filename = key
        expected_artifact = expected_artifacts.get(key)
        actual_artifact = actual_artifacts.get(key)
        if expected_artifact is None:
            findings.append(
                DistributionReproducibilityFinding(
                    role=role,
                    filename=filename,
                    expected=None,
                    actual=actual_artifact.sha256 if actual_artifact else None,
                    message=(
                        "rebuilt release produced an extra distribution artifact: "
                        f"{role} {filename}"
                    ),
                )
            )
            continue
        if actual_artifact is None:
            findings.append(
                DistributionReproducibilityFinding(
                    role=role,
                    filename=filename,
                    expected=expected_artifact.sha256,
                    actual=None,
                    message=(
                        "rebuilt release is missing a published distribution artifact: "
                        f"{role} {filename}"
                    ),
                )
            )
            continue
        if expected_artifact.sha256 != actual_artifact.sha256:
            findings.append(
                DistributionReproducibilityFinding(
                    role=role,
                    filename=filename,
                    expected=expected_artifact.sha256,
                    actual=actual_artifact.sha256,
                    message=(f"distribution artifact is not byte-reproducible: {role} {filename}"),
                )
            )
    return tuple(findings)


def _distribution_index(
    manifest: ReleaseArtifactManifest,
) -> dict[tuple[str, str], ReleaseArtifact]:
    return {
        (artifact.role, Path(artifact.path).name): artifact
        for artifact in manifest.artifacts
        if artifact.role in DIST_ROLES
    }


if __name__ == "__main__":
    raise SystemExit(main())
