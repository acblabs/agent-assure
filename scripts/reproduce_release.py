from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
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
# Per-release fixture date used to keep waiver evaluation and SOURCE_DATE_EPOCH
# stable. Update deliberately when preparing a new release evidence bundle.
RELEASE_TODAY = "2026-07-03"
RELEASE_SOURCE_DATE_EPOCH = str(
    int(datetime.fromisoformat(RELEASE_TODAY).replace(tzinfo=UTC).timestamp())
)


@dataclass(frozen=True)
class ReleaseCommand:
    name: str
    command: list[str]
    expected_exit: int


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
    release_today: str = RELEASE_TODAY,
) -> tuple[ReleaseCommand, ...]:
    _require_release_input_path(suite, field_name="suite")
    _require_release_input_path(baseline_variant, field_name="baseline_variant")
    _require_release_input_path(candidate_variant, field_name="candidate_variant")
    compiled = out / f"{artifact_prefix}.compiled.json"
    fixtures = out / f"{artifact_prefix}.fixtures.json"
    baseline = out / f"{artifact_prefix}.baseline.json"
    candidate = out / f"{artifact_prefix}.evidence-candidate.json"
    reports = out / "reports"
    return (
        ReleaseCommand(
            "compile",
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
            expected_exit=0,
        ),
        ReleaseCommand(
            "baseline-run",
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
            expected_exit=0,
        ),
        ReleaseCommand(
            "candidate-run",
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
            expected_exit=0,
        ),
        ReleaseCommand(
            "ci-gate",
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
                "--today",
                release_today,
            ],
            expected_exit=1,
        ),
    )


def run_release_commands(commands: tuple[ReleaseCommand, ...], *, logs_dir: Path) -> int:
    logs_dir.mkdir(parents=True, exist_ok=True)
    for release_command in commands:
        result = _run_logged(release_command, logs_dir=logs_dir)
        if result.returncode != release_command.expected_exit:
            command_text = " ".join(str(part) for part in release_command.command)
            print(
                "expected exit "
                f"{release_command.expected_exit}, got {result.returncode}: {command_text}",
                file=sys.stderr,
            )
            print(
                f"release command log: {logs_dir / f'{release_command.name}.log'}",
                file=sys.stderr,
            )
            return result.returncode or 3
    return 0


def _run_logged(
    release_command: ReleaseCommand,
    *,
    logs_dir: Path,
) -> subprocess.CompletedProcess[str]:
    log_path = logs_dir / f"{release_command.name}.log"
    command_text = " ".join(str(part) for part in release_command.command)
    with log_path.open("w", encoding="utf-8", newline="\n") as log:
        log.write(f"$ {command_text}\n")
        log.flush()
        process = subprocess.Popen(
            release_command.command,
            cwd=ROOT,
            env=_release_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if process.stdout is None:
            raise RuntimeError("release command stdout was not captured")
        for line in process.stdout:
            print(line, end="")
            log.write(line)
        returncode = process.wait()
        log.write(f"\n[exit {returncode}]\n")
    return subprocess.CompletedProcess(release_command.command, returncode)


def _release_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("SOURCE_DATE_EPOCH", RELEASE_SOURCE_DATE_EPOCH)
    return env


def _require_release_input_path(value: str, *, field_name: str) -> None:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (ROOT / path).resolve()
    resolved_root = ROOT.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must stay under the repository root: {resolved}"
        ) from exc


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
