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

from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest  # noqa: E402
from scripts.cosign_release_artifacts import release_artifacts  # noqa: E402

DIST_ROLES = frozenset({"python-distribution", "python-wheel", "source-distribution"})


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
            "After a successful comparison, copy only independently rebuilt, "
            "signable blobs into this new directory."
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
    """Stage only independently rebuilt signing inputs after byte verification."""

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
    destination.mkdir(parents=True)
    for relative_path in sorted(source):
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
                    message=(
                        "distribution artifact is not byte-reproducible: "
                        f"{role} {filename}"
                    ),
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
