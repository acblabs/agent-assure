from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / ".tmp" / "release"
CLI = [sys.executable, "-m", "agent_assure.cli.main"]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    commands = [
        (
            CLI
            + [
                "suite",
                "compile",
                "examples/prior_auth_synthetic/suite.yaml",
                "--out",
                str(OUT / "prior-auth.compiled.json"),
                "--manifest",
                str(OUT / "prior-auth.fixtures.json"),
            ],
            0,
        ),
        (
            CLI
            + [
                "suite",
                "run",
                str(OUT / "prior-auth.compiled.json"),
                "--variant",
                "examples/prior_auth_synthetic/variants/baseline.yaml",
                "--manifest",
                str(OUT / "prior-auth.fixtures.json"),
                "--out",
                str(OUT / "prior-auth.baseline.json"),
            ],
            0,
        ),
        (
            CLI
            + [
                "suite",
                "run",
                str(OUT / "prior-auth.compiled.json"),
                "--variant",
                "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml",
                "--manifest",
                str(OUT / "prior-auth.fixtures.json"),
                "--out",
                str(OUT / "prior-auth.evidence-candidate.json"),
            ],
            0,
        ),
        (
            CLI
            + [
                "ci",
                str(OUT / "prior-auth.evidence-candidate.json"),
                "--suite",
                str(OUT / "prior-auth.compiled.json"),
                "--out-dir",
                str(OUT / "reports"),
                "--baseline",
                str(OUT / "prior-auth.baseline.json"),
                "--report-mode",
                "full",
            ],
            1,
        ),
    ]
    for command, expected_exit in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != expected_exit:
            command_text = " ".join(command)
            print(
                f"expected exit {expected_exit}, got {result.returncode}: {command_text}",
                file=sys.stderr,
            )
            return result.returncode or 3
    print(f"release reproduction artifacts: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
