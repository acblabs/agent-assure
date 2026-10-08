from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
for source_root in (ROOT, ROOT / "src"):
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

import scripts.check_release_claim_profile as claim_profile  # noqa: E402
from agent_assure.artifact_io import ensure_unlinked_directory  # noqa: E402
from agent_assure.reporting.mutation import _mutation_output_lock  # noqa: E402

EVIDENCE_RELATIVE = Path("evidence/synthetic/release-control-efficacy")
PROFILE_RELATIVE = claim_profile.PROFILE_PATH.relative_to(claim_profile.ROOT)
CONFIG_NAME = "controls-mutation.yaml"
THREAT_NAME = "threat-applicability.yaml"
RUNTIME_LOCK_RELATIVE = EVIDENCE_RELATIVE / "mutation-results/.agent-assure-mutation.lock"
EVALUATION_DATE = "2026-07-20"
CAMPAIGN_SEED = "20260720"
WINDOWS_REPARSE_POINT = 0x0400

PRESERVED_TOP_LEVEL = frozenset({CONFIG_NAME, THREAT_NAME})
GENERATED_TOP_LEVEL = frozenset(
    {
        "assurance-evidence-graph.json",
        "control-efficacy",
        "dependency-inventory.json",
        "evaluation",
        "evidence-packet.json",
        "evidence-packet.md",
        "fixtures.json",
        "mutation-results",
        "release-artifact-manifest.json",
        "runset.json",
        "suite.compiled.json",
    }
)
EXPECTED_TOP_LEVEL = PRESERVED_TOP_LEVEL | GENERATED_TOP_LEVEL
CONFIG_VERSION_PATTERN = re.compile(r'^package_version: "[^"]+"$', re.MULTILINE)


def _project_version(root: Path) -> str:
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version: object = payload["project"]["version"]
    if not isinstance(version, str):
        raise ValueError("project version must be a string")
    return version


def _source_version(root: Path) -> str:
    text = (root / "src" / "agent_assure" / "__init__.py").read_text(encoding="utf-8")
    matches: list[str] = re.findall(
        r'^__version__ = "([^"]+)"$',
        text,
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise ValueError("source package must declare exactly one canonical __version__")
    return matches[0]


def _render_config(text: str, *, expected_release: str) -> str:
    matches = CONFIG_VERSION_PATTERN.findall(text)
    if len(matches) != 1:
        raise ValueError("controls-mutation config must declare package_version exactly once")
    return CONFIG_VERSION_PATTERN.sub(
        f'package_version: "{expected_release}"',
        text,
        count=1,
    )


def _assert_safe_entry(path: Path) -> None:
    metadata = os.lstat(path)
    attributes = getattr(metadata, "st_file_attributes", 0)
    if stat.S_ISLNK(metadata.st_mode) or attributes & WINDOWS_REPARSE_POINT:
        raise ValueError(f"release-control-efficacy tree contains a link or reparse point: {path}")
    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
        raise ValueError(f"release-control-efficacy file must be singly linked: {path}")
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
        raise ValueError(f"release-control-efficacy tree contains a special entry: {path}")


def _validate_inventory(evidence_root: Path, *, require_complete: bool = True) -> None:
    ensure_unlinked_directory(evidence_root)
    _assert_safe_entry(evidence_root)
    actual = {path.name for path in evidence_root.iterdir()}
    missing_authored = PRESERVED_TOP_LEVEL - actual
    unexpected = actual - EXPECTED_TOP_LEVEL
    if missing_authored:
        raise ValueError(
            f"release-control-efficacy authored inputs are missing: {sorted(missing_authored)}"
        )
    if unexpected:
        raise ValueError(
            f"release-control-efficacy tree has unexpected top-level entries: {sorted(unexpected)}"
        )
    if require_complete and actual != EXPECTED_TOP_LEVEL:
        missing = EXPECTED_TOP_LEVEL - actual
        raise ValueError(
            f"release-control-efficacy generated outputs are missing: {sorted(missing)}"
        )
    for directory, directory_names, file_names in os.walk(evidence_root, followlinks=False):
        base = Path(directory)
        for name in (*directory_names, *file_names):
            _assert_safe_entry(base / name)


def _run_source_cli(root: Path, *arguments: str) -> None:
    command = (sys.executable, str(root / "scripts" / "run_source_cli.py"), *arguments)
    print("+", subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=root, check=True)


def _git(
    root: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ("git", "-C", str(root), *arguments),
        input=input_bytes,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _write_text_atomic(path: Path, text: str) -> None:
    ensure_unlinked_directory(path.parent)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
            temporary_path = Path(handle.name)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _refresh_profile_digests(
    profile_path: Path,
    *,
    packet_path: Path,
    policy_path: Path,
) -> None:
    profile = claim_profile._load_profile(profile_path)
    normalized = deepcopy(profile)
    evidence = normalized.get("control_efficacy_evidence")
    if not isinstance(evidence, dict):
        raise ValueError("publication claim profile is missing control_efficacy_evidence")
    evidence["packet_sha256"] = "BOUND_FROM_REPOSITORY_BYTES"
    evidence["policy_sha256"] = "BOUND_FROM_REPOSITORY_BYTES"
    if normalized != claim_profile.EXPECTED_PROFILE:
        raise ValueError(
            "refusing to refresh digests in a publication claim profile with other changes"
        )
    profile_evidence = cast(dict[str, Any], profile["control_efficacy_evidence"])
    profile_evidence["packet_sha256"] = _sha256(packet_path)
    profile_evidence["policy_sha256"] = _sha256(policy_path)
    _write_text_atomic(
        profile_path,
        json.dumps(profile, indent=2, ensure_ascii=False) + "\n",
    )


def _require_clean_committed_worktree(root: Path) -> str:
    for arguments in (("diff", "--quiet"), ("diff", "--cached", "--quiet")):
        result = subprocess.run(("git", "-C", str(root), *arguments), check=False)
        if result.returncode == 1:
            raise ValueError("regeneration requires a clean committed worktree")
        if result.returncode != 0:
            raise OSError("could not verify the worktree state")
    head = _git(root, "rev-parse", "--verify", "HEAD", capture=True).stdout.decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("regeneration requires a full committed HEAD")
    return head


def _remove_generated_in_worktree(worktree: Path) -> None:
    relative_paths = [str(EVIDENCE_RELATIVE / name) for name in sorted(GENERATED_TOP_LEVEL)]
    _git(
        worktree,
        "rm",
        "-r",
        "--ignore-unmatch",
        "--",
        *relative_paths,
    )


def _remove_isolated_runtime_lock(worktree: Path) -> None:
    lock_path = worktree / RUNTIME_LOCK_RELATIVE
    if not lock_path.exists() and not lock_path.is_symlink():
        return
    _assert_safe_entry(lock_path)
    metadata = os.lstat(lock_path)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("isolated mutation runtime lock must be a regular file")
    lock_path.unlink()


def _build_scoped_patch(worktree: Path) -> bytes:
    _remove_isolated_runtime_lock(worktree)
    _git(
        worktree,
        "add",
        "-f",
        "--",
        EVIDENCE_RELATIVE.as_posix(),
        PROFILE_RELATIVE.as_posix(),
    )
    return _git(
        worktree,
        "diff",
        "--cached",
        "--binary",
        "--full-index",
        "HEAD",
        "--",
        EVIDENCE_RELATIVE.as_posix(),
        PROFILE_RELATIVE.as_posix(),
        capture=True,
    ).stdout


def _generate_in_worktree(worktree: Path, *, expected_release: str) -> bytes:
    evidence_root = worktree / EVIDENCE_RELATIVE
    config_path = evidence_root / CONFIG_NAME
    profile_path = worktree / PROFILE_RELATIVE
    _validate_inventory(evidence_root)
    config = _render_config(
        config_path.read_text(encoding="utf-8"),
        expected_release=expected_release,
    )
    _remove_generated_in_worktree(worktree)
    _write_text_atomic(config_path, config)

    suite = evidence_root / "suite.compiled.json"
    fixtures = evidence_root / "fixtures.json"
    runset = evidence_root / "runset.json"
    evaluation = evidence_root / "evaluation"
    mutation_results = evidence_root / "mutation-results"
    efficacy_report = evidence_root / "control-efficacy" / "control-efficacy-report.json"
    packet = evidence_root / "evidence-packet.json"

    _run_source_cli(
        worktree,
        "suite",
        "compile",
        str(worktree / "examples" / "prior_auth_synthetic" / "suite.yaml"),
        "--out",
        str(suite),
        "--manifest",
        str(fixtures),
    )
    _run_source_cli(
        worktree,
        "suite",
        "run",
        str(suite),
        "--variant",
        str(worktree / "examples" / "prior_auth_synthetic" / "variants" / "baseline.yaml"),
        "--manifest",
        str(fixtures),
        "--out",
        str(runset),
    )
    _run_source_cli(
        worktree,
        "evaluate",
        str(runset),
        "--suite",
        str(suite),
        "--out-dir",
        str(evaluation),
        "--today",
        EVALUATION_DATE,
    )
    _run_source_cli(worktree, "doctor", "controls-mutate", "--config", str(config_path))
    _run_source_cli(
        worktree,
        "controls",
        "mutate",
        "--suite",
        str(suite),
        "--runset",
        str(runset),
        "--catalog",
        "core/v1",
        "--full-report",
        "--seed",
        CAMPAIGN_SEED,
        "--today",
        EVALUATION_DATE,
        "--out",
        str(mutation_results),
    )
    _run_source_cli(worktree, "controls", "efficacy", "--config", str(config_path))
    _run_source_cli(
        worktree,
        "packet",
        "build",
        str(evaluation / "evaluation-summary.json"),
        "--control-efficacy",
        str(efficacy_report),
        "--efficacy-config",
        str(config_path),
        "--out",
        str(packet),
        "--project-root",
        str(worktree),
    )
    _run_source_cli(
        worktree,
        "ci",
        "gate",
        str(packet),
        "--artifact-root",
        str(worktree),
        "--release-profile",
        "--efficacy-policy",
        str(config_path),
    )
    _refresh_profile_digests(
        profile_path,
        packet_path=packet,
        policy_path=config_path,
    )
    _validate_inventory(evidence_root)
    subprocess.run(
        (
            sys.executable,
            str(worktree / "scripts" / "check_release_claim_profile.py"),
            "--expected-release",
            expected_release,
        ),
        cwd=worktree,
        check=True,
    )
    return _build_scoped_patch(worktree)


def _apply_generated_patch(root: Path, patch: bytes) -> None:
    if not patch:
        return
    evidence_root = root / EVIDENCE_RELATIVE
    _validate_inventory(evidence_root)
    mutation_root = evidence_root / "mutation-results"
    with _mutation_output_lock(mutation_root):
        _git(root, "apply", "--whitespace=nowarn", "-", input_bytes=patch)
    _validate_inventory(evidence_root)


def regenerate(*, expected_release: str, replace_generated: bool) -> None:
    if claim_profile.RELEASE_PATTERN.fullmatch(expected_release) is None:
        raise ValueError("expected release must be 0.7.0 or a canonical 0.7.0rcN candidate")
    versions = {
        "pyproject": _project_version(ROOT),
        "source": _source_version(ROOT),
        "installed": importlib.metadata.version("agent-assure"),
    }
    mismatched = {name: value for name, value in versions.items() if value != expected_release}
    if mismatched:
        raise ValueError(
            f"release-control-efficacy version mismatch for {expected_release}: {mismatched}"
        )
    if not replace_generated:
        raise ValueError("regeneration requires explicit --replace-generated authorization")

    head = _require_clean_committed_worktree(ROOT)
    _validate_inventory(ROOT / EVIDENCE_RELATIVE)
    temporary_parent = Path(tempfile.mkdtemp(prefix="agent-assure-efficacy-"))
    worktree = temporary_parent / "repository"
    worktree_added = False
    try:
        _git(ROOT, "worktree", "add", "--detach", str(worktree), head)
        worktree_added = True
        patch = _generate_in_worktree(worktree, expected_release=expected_release)
    finally:
        if worktree_added:
            subprocess.run(
                ("git", "-C", str(ROOT), "worktree", "remove", "--force", str(worktree)),
                check=False,
            )
        if temporary_parent.exists():
            shutil.rmtree(temporary_parent)

    _apply_generated_patch(ROOT, patch)
    subprocess.run(
        (
            sys.executable,
            str(ROOT / "scripts" / "check_release_claim_profile.py"),
            "--expected-release",
            expected_release,
        ),
        cwd=ROOT,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate the fixed v0.7.0 synthetic release bundle in an isolated "
            "committed worktree and refresh its claim-profile digest bindings."
        )
    )
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--replace-generated", action="store_true")
    args = parser.parse_args(argv)
    try:
        regenerate(
            expected_release=args.expected_release,
            replace_generated=args.replace_generated,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"release-control-efficacy-regenerate: {exc}", file=sys.stderr)
        return 1
    print(f"release-control-efficacy-regenerate: ok (expected-release={args.expected_release})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
