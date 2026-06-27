from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.release_evidence import (  # noqa: E402
    CORE_RELEASE_ROLES,
    build_digest_replay,
    load_digest_replay,
    verify_digest_replay,
    write_digest_replay,
)

DEFAULT_OUT = ROOT / ".tmp" / "release"
CLI = [sys.executable, "-m", "agent_assure.cli.main"]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce the flagship release evidence artifacts."
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--write-digests", type=Path, default=None)
    parser.add_argument("--expected-digests", type=Path, default=None)
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

    replay = build_digest_replay(
        release_artifacts(out, artifact_prefix=args.artifact_prefix),
        project_root=ROOT,
        source_ref=args.source_ref or os.environ.get("GITHUB_REF"),
    )
    replay_path = args.write_digests
    if replay_path is None:
        suffix = "actual" if args.expected_digests is not None else ""
        replay_path = out / f"release-digest-replay{'.' + suffix if suffix else ''}.json"
    write_digest_replay(replay, replay_path)

    if args.expected_digests is not None:
        expected = load_digest_replay(args.expected_digests)
        verification = verify_digest_replay(
            expected,
            artifact_root=ROOT,
            required_roles=CORE_RELEASE_ROLES,
            require_current_commit=True,
        )
        if not verification.ok:
            print(
                json.dumps(
                    {
                        "artifact_kind": expected.artifact_kind,
                        "exit_code": 1,
                        "findings": [
                            {
                                "role": finding.role,
                                "path": finding.path,
                                "expected": finding.expected,
                                "actual": finding.actual,
                                "message": finding.message,
                            }
                            for finding in verification.findings
                        ],
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1
        print(f"release digest replay matched: {args.expected_digests}")

    print(f"release reproduction artifacts: {out}")
    print(f"release digest replay: {replay_path}")
    return 0


def release_commands(
    out: Path,
    *,
    suite: str,
    baseline_variant: str,
    candidate_variant: str,
    artifact_prefix: str,
) -> tuple[tuple[list[str], int], ...]:
    compiled = out / f"{artifact_prefix}.compiled.json"
    fixtures = out / f"{artifact_prefix}.fixtures.json"
    baseline = out / f"{artifact_prefix}.baseline.json"
    candidate = out / f"{artifact_prefix}.evidence-candidate.json"
    reports = out / "reports"
    return (
        (
            CLI
            + [
                "suite",
                "compile",
                suite,
                "--out",
                str(compiled),
                "--manifest",
                str(fixtures),
            ],
            0,
        ),
        (
            CLI
            + [
                "suite",
                "run",
                str(compiled),
                "--variant",
                baseline_variant,
                "--manifest",
                str(fixtures),
                "--out",
                str(baseline),
            ],
            0,
        ),
        (
            CLI
            + [
                "suite",
                "run",
                str(compiled),
                "--variant",
                candidate_variant,
                "--manifest",
                str(fixtures),
                "--out",
                str(candidate),
            ],
            0,
        ),
        (
            CLI
            + [
                "ci",
                str(candidate),
                "--suite",
                str(compiled),
                "--out-dir",
                str(reports),
                "--baseline",
                str(baseline),
                "--report-mode",
                "full",
            ],
            1,
        ),
    )


def release_artifacts(out: Path, *, artifact_prefix: str) -> tuple[tuple[str, Path], ...]:
    return (
        ("compiled-suite", out / f"{artifact_prefix}.compiled.json"),
        ("fixture-manifest", out / f"{artifact_prefix}.fixtures.json"),
        ("evidence-packet", out / "reports" / "evidence-packet.json"),
        (
            "release-artifact-manifest",
            out / "reports" / "release-artifact-manifest.json",
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
