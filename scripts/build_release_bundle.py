from __future__ import annotations

import argparse
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for import_path in (ROOT, SRC, SCRIPTS):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from agent_assure.artifact_io import git_output  # noqa: E402
from agent_assure.release_evidence import build_digest_replay, write_digest_replay  # noqa: E402
from agent_assure.reporting.environment import (  # noqa: E402
    build_release_manifest,
    release_artifact,
    write_release_manifest,
)
from agent_assure.reporting.packet import (  # noqa: E402
    load_evidence_packet,
    packet_summary_files_binding_error,
    write_evidence_packet,
    write_evidence_packet_markdown,
)
from agent_assure.reporting.sbom import build_sbom, write_sbom  # noqa: E402
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest  # noqa: E402
from agent_assure.schema.validation import (  # noqa: E402
    load_validated_artifact_payload,
    project_validated_artifact_payload,
)
from scripts.check_mutation_release_provenance import (  # noqa: E402
    registered_release_provenance_failures,
)
from scripts.reproduce_release import (  # noqa: E402
    ReleaseCommand,
    release_artifacts,
    release_commands,
    run_release_commands,
)

DEFAULT_OUT = ROOT / ".tmp" / "release"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build release evidence, SBOM, distribution, and replay artifacts."
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--write-digests", type=Path, default=None)
    parser.add_argument("--source-ref", default=None)
    parser.add_argument(
        "--expected-release",
        required=True,
        help="Package/tag release version that mutation provenance must declare.",
    )
    parser.add_argument("--suite", default="examples/prior_auth_synthetic/suite.yaml")
    parser.add_argument(
        "--baseline-variant",
        default="examples/prior_auth_synthetic/variants/baseline.yaml",
    )
    parser.add_argument(
        "--candidate-variant",
        default="examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml",
    )
    parser.add_argument("--artifact-prefix", default="prior-auth")
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip Python sdist/wheel build and emit only evidence plus SBOM.",
    )
    parser.add_argument(
        "--require-clean-source",
        action="store_true",
        help="Fail before and after generation unless the Git source tree is clean.",
    )
    args = parser.parse_args(argv)

    if args.require_clean_source and not _require_clean_source("before release generation"):
        return 2

    provenance_failures = registered_release_provenance_failures(
        expected_release=args.expected_release,
    )
    if provenance_failures:
        print("release provenance validation failed:", file=sys.stderr)
        for failure in provenance_failures:
            print(f"- {failure}", file=sys.stderr)
        return 2

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    try:
        commands = release_commands(
            out,
            suite=args.suite,
            baseline_variant=args.baseline_variant,
            candidate_variant=args.candidate_variant,
            artifact_prefix=args.artifact_prefix,
        )
    except ValueError as exc:
        print(f"release input error: {exc}", file=sys.stderr)
        return 2
    command_exit = run_release_commands(
        commands,
        logs_dir=out / "logs",
    )
    if command_exit:
        return command_exit

    distribution_paths: tuple[Path, ...]
    if args.skip_build:
        distribution_paths = ()
    else:
        build_exit, distribution_paths = _build_distributions(out / "dist", logs_dir=out / "logs")
        if build_exit:
            return build_exit
    extra_artifacts = _write_release_sbom_and_manifest(
        out,
        artifact_prefix=args.artifact_prefix,
        distribution_paths=distribution_paths,
    )
    replay = build_digest_replay(
        release_artifacts(out, artifact_prefix=args.artifact_prefix),
        project_root=ROOT,
        source_ref=args.source_ref or os.environ.get("GITHUB_REF"),
    )
    replay_path = args.write_digests or out / "release-digest-replay.json"
    write_digest_replay(replay, replay_path)

    if args.require_clean_source and not _require_clean_source("after release generation"):
        return 2

    print(f"release bundle artifacts: {out}")
    print(f"release digest replay: {replay_path}")
    print("release manifest extras: " + ", ".join(artifact.role for artifact in extra_artifacts))
    return 0


def _build_distributions(dist_dir: Path, *, logs_dir: Path) -> tuple[int, tuple[Path, ...]]:
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir(parents=True)
    result = run_release_commands(
        (_distribution_command(dist_dir),),
        logs_dir=logs_dir,
    )
    if result:
        return result, ()
    try:
        artifacts = _validated_distribution_paths(dist_dir)
    except ValueError as exc:
        print(f"release distribution error: {exc}", file=sys.stderr)
        return 2, ()
    return 0, artifacts


def _validated_distribution_paths(dist_dir: Path) -> tuple[Path, ...]:
    entries = tuple(sorted(dist_dir.iterdir(), key=lambda path: path.name))
    unsafe = [path.name for path in entries if path.is_symlink() or not path.is_file()]
    if unsafe:
        raise ValueError(
            "distribution directory contains non-regular entries: " + ", ".join(unsafe)
        )
    wheels = tuple(path for path in entries if path.suffix == ".whl")
    sdists = tuple(path for path in entries if path.name.endswith(".tar.gz"))
    expected = {*wheels, *sdists}
    unexpected = [path.name for path in entries if path not in expected]
    if len(wheels) != 1 or len(sdists) != 1 or unexpected:
        details = [
            f"wheels={len(wheels)}",
            f"source-distributions={len(sdists)}",
        ]
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected))
        raise ValueError("expected exactly one wheel and one sdist (" + "; ".join(details) + ")")
    return tuple(entries)


def _require_clean_source(stage: str) -> bool:
    status = git_output(
        ROOT,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        allow_empty=True,
    )
    if status is None:
        print(f"release source validation failed {stage}: git status unavailable", file=sys.stderr)
        return False
    if status:
        print(f"release source validation failed {stage}: source tree is dirty", file=sys.stderr)
        print(status, file=sys.stderr)
        return False
    return True


def _distribution_command(dist_dir: Path) -> ReleaseCommand:
    return ReleaseCommand(
        "build-distributions",
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist_dir)],
        expected_exit=0,
    )


def _write_release_sbom_and_manifest(
    out: Path,
    *,
    artifact_prefix: str,
    distribution_paths: tuple[Path, ...],
) -> tuple[ReleaseArtifact, ...]:
    reports = out / "reports"
    manifest_path = reports / "release-artifact-manifest.json"
    packet_path = reports / "evidence-packet.json"
    packet_markdown_path = reports / "evidence-packet.md"
    existing_manifest = project_validated_artifact_payload(
        load_validated_artifact_payload(manifest_path, "release-artifact-manifest"),
        ReleaseArtifactManifest,
        kind="release-artifact-manifest",
    )
    environment = existing_manifest.environment
    sbom_path = out / "sbom.cdx.json"
    write_sbom(
        build_sbom(
            environment,
            distribution_paths=distribution_paths,
            project_root=ROOT,
        ),
        sbom_path,
    )
    extra_artifacts = (
        *tuple(_existing_release_artifacts(out, artifact_prefix=artifact_prefix)),
        release_artifact("sbom", sbom_path, project_root=ROOT),
        *(
            release_artifact(_distribution_role(path), path, project_root=ROOT)
            for path in distribution_paths
        ),
    )
    manifest = build_release_manifest(
        (*existing_manifest.artifacts, *extra_artifacts),
        environment=environment,
    )
    packet = load_evidence_packet(packet_path).model_copy(update={"release_manifest": manifest})
    binding_error = packet_summary_files_binding_error(packet, artifact_root=ROOT)
    if binding_error is not None:
        raise ValueError(f"release packet graph binding is invalid: {binding_error}")
    write_release_manifest(manifest, manifest_path)
    write_evidence_packet(packet, packet_path)
    write_evidence_packet_markdown(packet, packet_markdown_path)
    return extra_artifacts


def _existing_release_artifacts(out: Path, *, artifact_prefix: str) -> tuple[ReleaseArtifact, ...]:
    paths = (
        ("fixture-manifest", out / f"{artifact_prefix}.fixtures.json"),
        ("evaluation-report", out / "reports" / "evaluation-report.json"),
        ("comparison-report", out / "reports" / "comparison-report.json"),
    )
    return tuple(
        release_artifact(role, path, project_root=ROOT)
        for role, path in paths
        if path.exists()
    )


def _distribution_role(path: Path) -> str:
    if path.suffix == ".whl":
        return "python-wheel"
    if path.name.endswith(".tar.gz"):
        return "source-distribution"
    return "python-distribution"


if __name__ == "__main__":
    raise SystemExit(main())
