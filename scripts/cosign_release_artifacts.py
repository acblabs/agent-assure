from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RELEASE_DIR = ROOT / ".tmp" / "release"
DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    release_dir = _resolve_path(args.release_dir)
    try:
        if args.command == "sign":
            sign_artifacts(release_dir, cosign=args.cosign)
        elif args.command == "verify":
            verify_artifacts(
                release_dir,
                cosign=args.cosign,
                workflow_name=args.workflow_name,
                workflow_path=args.workflow_path,
                repository=args.repository,
                ref=args.ref,
                sha=args.sha,
                event_name=args.event_name,
                issuer=args.issuer,
            )
        elif args.command == "verify-modified-fails":
            verify_modified_packet_fails(
                release_dir,
                cosign=args.cosign,
                workflow_name=args.workflow_name,
                workflow_path=args.workflow_path,
                repository=args.repository,
                ref=args.ref,
                sha=args.sha,
                event_name=args.event_name,
                issuer=args.issuer,
            )
        else:
            raise ValueError(f"unknown command: {args.command}")
    except (RuntimeError, ValueError) as exc:
        print(f"cosign-release-artifacts: {exc}", file=sys.stderr)
        return 1
    return 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign or verify agent-assure release artifacts with cosign."
    )
    parser.add_argument("command", choices=("sign", "verify", "verify-modified-fails"))
    parser.add_argument("--release-dir", type=Path, default=DEFAULT_RELEASE_DIR)
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--workflow-name", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME", ""))
    parser.add_argument("--issuer", default=DEFAULT_ISSUER)
    return parser.parse_args(argv)


def sign_artifacts(release_dir: Path, *, cosign: str) -> None:
    for artifact in release_artifacts(release_dir):
        _run(
            [
                cosign,
                "sign-blob",
                "--yes",
                "--bundle",
                str(bundle_path(artifact)),
                str(artifact),
            ]
        )


def verify_artifacts(
    release_dir: Path,
    *,
    cosign: str,
    workflow_name: str,
    workflow_path: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    issuer: str,
) -> None:
    identity = workflow_identity(repository=repository, workflow_path=workflow_path, ref=ref)
    for artifact in release_artifacts(release_dir):
        verify_blob(
            artifact,
            cosign=cosign,
            identity=identity,
            issuer=issuer,
            workflow_name=workflow_name,
            repository=repository,
            ref=ref,
            sha=sha,
            event_name=event_name,
        )


def verify_modified_packet_fails(
    release_dir: Path,
    *,
    cosign: str,
    workflow_name: str,
    workflow_path: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    issuer: str,
) -> None:
    packet = release_dir / "reports" / "evidence-packet.json"
    modified_packet = packet.with_name("evidence-packet.modified.json")
    shutil.copy2(packet, modified_packet)
    try:
        with modified_packet.open("ab") as handle:
            handle.write(b"\nmodified\n")
        identity = workflow_identity(
            repository=repository,
            workflow_path=workflow_path,
            ref=ref,
        )
        result = verify_blob(
            modified_packet,
            cosign=cosign,
            identity=identity,
            issuer=issuer,
            workflow_name=workflow_name,
            repository=repository,
            ref=ref,
            sha=sha,
            event_name=event_name,
            bundle=bundle_path(packet),
            check=False,
        )
        if result.returncode == 0:
            raise RuntimeError("modified evidence packet unexpectedly verified")
    finally:
        modified_packet.unlink(missing_ok=True)


def release_artifacts(release_dir: Path) -> tuple[Path, ...]:
    fixed = (
        release_dir / "reports" / "evidence-packet.json",
        release_dir / "reports" / "evidence-packet.md",
        release_dir / "reports" / "release-artifact-manifest.json",
        release_dir / "release-digest-replay.json",
        release_dir / "sbom.cdx.json",
    )
    release_notes = release_dir / "release-notes.md"
    optional = (release_notes,) if release_notes.exists() else ()
    fixed_and_optional = (*fixed, *optional)
    missing = [
        path for path in fixed_and_optional if not path.is_file() or path.is_symlink()
    ]
    if missing:
        raise RuntimeError(
            "missing release artifact(s): "
            + ", ".join(_display_path(path) for path in missing)
        )
    dist_dir = release_dir / "dist"
    dist_artifacts = _distribution_artifacts(dist_dir)
    return (*fixed_and_optional, *dist_artifacts)


def _distribution_artifacts(dist_dir: Path) -> tuple[Path, Path]:
    if not dist_dir.is_dir() or dist_dir.is_symlink():
        raise RuntimeError(f"missing release distribution directory: {_display_path(dist_dir)}")
    entries = tuple(sorted(dist_dir.iterdir(), key=lambda path: path.name))
    unsafe = [path for path in entries if path.is_symlink() or not path.is_file()]
    if unsafe:
        raise RuntimeError(
            "non-regular release distribution entry: "
            + ", ".join(_display_path(path) for path in unsafe)
        )
    distributions = tuple(
        path
        for path in entries
        if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    wheels = tuple(path for path in distributions if path.suffix == ".whl")
    sdists = tuple(path for path in distributions if path.name.endswith(".tar.gz"))
    allowed_bundle_names = {f"{path.name}.bundle" for path in distributions}
    unexpected = [
        path
        for path in entries
        if path not in distributions and path.name not in allowed_bundle_names
    ]
    if len(wheels) != 1 or len(sdists) != 1 or unexpected:
        details = [
            f"{len(wheels)} wheel(s)",
            f"{len(sdists)} sdist(s)",
        ]
        if unexpected:
            details.append(
                "unexpected " + ", ".join(_display_path(path) for path in unexpected)
            )
        raise RuntimeError("invalid release distribution set: " + "; ".join(details))
    return wheels[0], sdists[0]


def verify_blob(
    artifact: Path,
    *,
    cosign: str,
    identity: str,
    issuer: str,
    workflow_name: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    bundle: Path | None = None,
    check: bool = True,
    attempts: int = 5,
) -> subprocess.CompletedProcess[str]:
    _require_identity_context(
        repository=repository,
        ref=ref,
        sha=sha,
        event_name=event_name,
    )
    command = [
        cosign,
        "verify-blob",
        str(artifact),
        "--bundle",
        str(bundle or bundle_path(artifact)),
        "--certificate-identity",
        identity,
        "--certificate-oidc-issuer",
        issuer,
        "--certificate-github-workflow-name",
        workflow_name,
        "--certificate-github-workflow-repository",
        repository,
        "--certificate-github-workflow-ref",
        ref,
        "--certificate-github-workflow-sha",
        sha,
        "--certificate-github-workflow-trigger",
        event_name,
    ]
    last_result: subprocess.CompletedProcess[str] | None = None
    for attempt in range(1, attempts + 1):
        print(f"verifying {_display_path(artifact)} (attempt {attempt})")
        result = _run(command, check=False)
        if result.returncode == 0 or not check:
            return result
        last_result = result
        time.sleep(attempt * 2)
    if last_result is None:
        raise RuntimeError(f"cosign verification did not run: {_display_path(artifact)}")
    raise RuntimeError(_command_failure(command, last_result))


def workflow_identity(*, repository: str, workflow_path: str, ref: str) -> str:
    _require_nonempty("repository", repository)
    _require_nonempty("workflow_path", workflow_path)
    _require_nonempty("ref", ref)
    return f"https://github.com/{repository}/{workflow_path}@{ref}"


def bundle_path(artifact: Path) -> Path:
    return artifact.with_name(f"{artifact.name}.bundle")


def _run(args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(args),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(_command_failure(args, result))
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result


def _command_failure(
    args: Sequence[str],
    result: subprocess.CompletedProcess[str],
) -> str:
    details = [
        f"command failed with exit {result.returncode}: {' '.join(args)}",
        result.stdout.strip(),
        result.stderr.strip(),
    ]
    return "\n".join(detail for detail in details if detail)


def _require_identity_context(
    *,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
) -> None:
    _require_nonempty("repository", repository)
    _require_nonempty("ref", ref)
    _require_nonempty("sha", sha)
    _require_nonempty("event_name", event_name)


def _require_nonempty(name: str, value: str) -> None:
    if not value:
        raise ValueError(f"{name} is required")


def _resolve_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return ROOT / path


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
