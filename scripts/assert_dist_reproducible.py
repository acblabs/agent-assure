from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest  # noqa: E402
from agent_assure.schema.validation import load_json  # noqa: E402

DIST_ROLES = frozenset({"python-distribution", "python-wheel", "source-distribution"})


@dataclass(frozen=True)
class DistributionReproducibilityFinding:
    role: str
    filename: str
    expected: str | None
    actual: str | None
    message: str


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare published and rebuilt distribution hashes in release manifests."
    )
    parser.add_argument("expected_manifest", type=Path)
    parser.add_argument("actual_manifest", type=Path)
    parser.add_argument(
        "--require-distributions",
        action="store_true",
        help="Fail when the expected manifest contains no wheel/sdist distribution entries.",
    )
    args = parser.parse_args(argv)

    expected = ReleaseArtifactManifest.model_validate(load_json(args.expected_manifest))
    actual = ReleaseArtifactManifest.model_validate(load_json(args.actual_manifest))
    findings = compare_distribution_artifacts(
        expected,
        actual,
        require_distributions=args.require_distributions,
    )
    if findings:
        print(
            json.dumps(
                {
                    "artifact_kind": "distribution-reproducibility-check",
                    "exit_code": 1,
                    "findings": [
                        {
                            "role": finding.role,
                            "filename": finding.filename,
                            "expected": finding.expected,
                            "actual": finding.actual,
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

    count = len(_distribution_index(expected))
    print(f"distribution artifacts byte-reproducible: {count} artifacts")
    return 0


def compare_distribution_artifacts(
    expected: ReleaseArtifactManifest,
    actual: ReleaseArtifactManifest,
    *,
    require_distributions: bool = False,
) -> tuple[DistributionReproducibilityFinding, ...]:
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
