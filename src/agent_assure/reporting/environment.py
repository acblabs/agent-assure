from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from importlib import metadata
from pathlib import Path

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.schema.environment import EnvironmentInfo, InstalledPackage
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest

LOCKFILE_CANDIDATES = (
    "uv.lock",
    "requirements.lock",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
)


def collect_environment(
    *,
    project_root: Path,
    dependency_inventory_path: Path | None = None,
    dependency_inventory_digest: str | None = None,
) -> EnvironmentInfo:
    lockfile = _first_existing(project_root, LOCKFILE_CANDIDATES)
    return EnvironmentInfo(
        artifact_kind="environment-info",
        platform=platform.platform(),
        python_version=_python_version(),
        git_commit=_git_output(project_root, "rev-parse", "HEAD"),
        git_dirty=_git_dirty(project_root),
        lockfile_path=_relative_path(lockfile, project_root) if lockfile else None,
        lockfile_digest=_file_sha256(lockfile) if lockfile else None,
        dependency_inventory_path=(
            _relative_path(dependency_inventory_path, project_root)
            if dependency_inventory_path
            else None
        ),
        dependency_inventory_digest=dependency_inventory_digest,
        installed_packages=_installed_packages(),
    )


def write_dependency_inventory(environment: EnvironmentInfo, path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "artifact_kind": "dependency-inventory",
        "format": "agent-assure-dependency-inventory-v0.1",
        "metadata": {
            "tool": "agent-assure",
            "python_version": environment.python_version,
            "platform": environment.platform,
        },
        "components": [
            {
                "type": "library",
                "name": package.name,
                "version": package.version,
            }
            for package in environment.installed_packages
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return _file_sha256(path)


def environment_with_dependency_inventory(project_root: Path, out_dir: Path) -> EnvironmentInfo:
    initial = collect_environment(project_root=project_root)
    inventory_path = out_dir / "dependency-inventory.json"
    inventory_digest = write_dependency_inventory(initial, inventory_path)
    return collect_environment(
        project_root=project_root,
        dependency_inventory_path=inventory_path,
        dependency_inventory_digest=inventory_digest,
    )


def attach_evaluation_environment(
    report: EvaluationReport,
    environment: EnvironmentInfo,
) -> EvaluationReport:
    summary = report.candidate_vs_expectations.model_copy(update={"environment": environment})
    return report.model_copy(
        update={"candidate_vs_expectations": summary, "environment": environment}
    )


def attach_comparison_environment(
    report: ComparisonReport,
    environment: EnvironmentInfo,
) -> ComparisonReport:
    summary = report.comparison_summary.model_copy(update={"environment": environment})
    candidate = report.candidate_vs_expectations.model_copy(update={"environment": environment})
    baseline = report.baseline_vs_expectations.model_copy(update={"environment": environment})
    return report.model_copy(
        update={
            "comparison_summary": summary,
            "candidate_vs_expectations": candidate,
            "baseline_vs_expectations": baseline,
            "environment": environment,
        }
    )


def release_artifact(
    role: str,
    path: Path,
    *,
    project_root: Path,
) -> ReleaseArtifact:
    return ReleaseArtifact(
        artifact_kind="release-artifact",
        role=role,
        path=_relative_path(path, project_root),
        sha256=_file_sha256(path),
    )


def build_release_manifest(
    artifacts: tuple[ReleaseArtifact, ...],
    *,
    environment: EnvironmentInfo,
    manifest_id: str | None = None,
) -> ReleaseArtifactManifest:
    payload = {
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
        "environment": environment.model_dump(mode="json"),
    }
    return ReleaseArtifactManifest(
        artifact_kind="release-artifact-manifest",
        manifest_id=manifest_id or f"manifest-{sha256_hexdigest(payload)[:16]}",
        artifacts=artifacts,
        environment=environment,
    )


def write_release_manifest(manifest: ReleaseArtifactManifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _installed_packages() -> tuple[InstalledPackage, ...]:
    packages = [
        InstalledPackage(
            artifact_kind="installed-package",
            name=_package_name(dist),
            version=dist.version,
        )
        for dist in metadata.distributions()
    ]
    return tuple(sorted(packages, key=lambda package: (package.name.lower(), package.version)))


def _python_version() -> str:
    return platform.python_version()


def _package_name(dist: metadata.Distribution) -> str:
    name = dist.metadata["Name"]
    return name if name else "unknown"


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


def _git_dirty(project_root: Path) -> bool | None:
    output = _git_output(project_root, "status", "--porcelain")
    if output is None:
        return None
    return bool(output)


def _first_existing(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        path = root / name
        if path.exists() and path.is_file():
            return path
    return None


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
