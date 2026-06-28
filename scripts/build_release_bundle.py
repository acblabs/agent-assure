from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for import_path in (SRC, SCRIPTS):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from reproduce_release import release_artifacts, release_commands  # noqa: E402

from agent_assure.release_evidence import build_digest_replay, write_digest_replay  # noqa: E402
from agent_assure.reporting.environment import (  # noqa: E402
    build_release_manifest,
    release_artifact,
    write_release_manifest,
)
from agent_assure.reporting.packet import (  # noqa: E402
    load_evidence_packet,
    write_evidence_packet,
    write_evidence_packet_markdown,
)
from agent_assure.reporting.sbom import build_sbom, write_sbom  # noqa: E402
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest  # noqa: E402
from agent_assure.schema.validation import load_json  # noqa: E402

DEFAULT_OUT = ROOT / ".tmp" / "release"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build release evidence, SBOM, distribution, and replay artifacts."
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--write-digests", type=Path, default=None)
    parser.add_argument("--source-ref", default=None)
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
    args = parser.parse_args(argv)

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    for command, expected_exit in release_commands(
        out,
        suite=args.suite,
        baseline_variant=args.baseline_variant,
        candidate_variant=args.candidate_variant,
        artifact_prefix=args.artifact_prefix,
    ):
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != expected_exit:
            command_text = " ".join(str(part) for part in command)
            print(
                f"expected exit {expected_exit}, got {result.returncode}: {command_text}",
                file=sys.stderr,
            )
            return result.returncode or 3

    distribution_paths: tuple[Path, ...]
    if args.skip_build:
        distribution_paths = ()
    else:
        build_exit, distribution_paths = _build_distributions(out / "dist")
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

    print(f"release bundle artifacts: {out}")
    print(f"release digest replay: {replay_path}")
    print("release manifest extras: " + ", ".join(artifact.role for artifact in extra_artifacts))
    return 0


def _build_distributions(dist_dir: Path) -> tuple[int, tuple[Path, ...]]:
    dist_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist_dir)],
        cwd=ROOT,
        check=False,
    )
    if result.returncode:
        return result.returncode, ()
    return 0, tuple(sorted(path for path in dist_dir.iterdir() if path.is_file()))


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
    existing_manifest = ReleaseArtifactManifest.model_validate(load_json(manifest_path))
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
    write_release_manifest(manifest, manifest_path)
    packet = load_evidence_packet(packet_path).model_copy(update={"release_manifest": manifest})
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
