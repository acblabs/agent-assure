from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = (
    ROOT / "src" / "agent_assure" / "release_trust" / "v0_7_0" / "publication-claim-profile.json"
)
MAX_PROFILE_BYTES = 64 * 1024
MAX_EFFICACY_BINDING_BYTES = 2 * 1024 * 1024
RELEASE_PATTERN = re.compile(r"^0\.7\.0(?:rc[1-9]\d*)?$")
EFFICACY_PACKET_PATH = Path("evidence/synthetic/release-control-efficacy/evidence-packet.json")
EFFICACY_POLICY_PATH = Path("evidence/synthetic/release-control-efficacy/controls-mutation.yaml")
EFFICACY_DEPENDENCY_INVENTORY_PATHS = (
    Path("evidence/synthetic/release-control-efficacy/dependency-inventory.json"),
    Path("evidence/synthetic/release-control-efficacy/evaluation/dependency-inventory.json"),
)
EFFICACY_VERSION_BEARING_JSON_PATHS = (
    *EFFICACY_DEPENDENCY_INVENTORY_PATHS,
    Path("evidence/synthetic/release-control-efficacy/evaluation/evaluation-report.json"),
    Path("evidence/synthetic/release-control-efficacy/evaluation/evaluation-summary.json"),
    Path("evidence/synthetic/release-control-efficacy/evaluation/release-artifact-manifest.json"),
    Path("evidence/synthetic/release-control-efficacy/release-artifact-manifest.json"),
    EFFICACY_PACKET_PATH,
)

CANONICAL_DISCLOSURE = (
    "The v0.7.0 release line is bounded to engineering qualification and committed "
    "deterministic-fixture artifact validation. No real-model study, "
    "qualifying external pilot, independent empirical review, or frozen confirmatory benchmark "
    "is included. The release therefore makes no empirical-effectiveness, external-validity, "
    "population-generalization, production-control-effectiveness, provider-quality, safety, "
    "compliance, or deployment-fitness claim. Those artifacts are prerequisites only for the "
    "corresponding empirical claim, not for distribution of this bounded release."
)

EXPECTED_PROFILE: dict[str, Any] = {
    "artifact_kind": "publication-claim-profile",
    "schema_version": "1.0.0",
    "profile_id": "bounded-non-empirical/v1",
    "release_line": "0.7.0",
    "maturity": "beta",
    "qualification_scope": [
        "packaged-implementation",
        "versioned-schemas",
        "committed-deterministic-fixture-artifact-validation",
        "cross-platform-ci",
        "dependency-audits",
        "same-toolchain-fresh-job-byte-matching",
        "provenance",
        "signing",
        "trusted-publishing",
    ],
    "control_efficacy_basis": "committed-deterministic-synthetic-artifacts-only",
    "control_efficacy_evidence": {
        "verification_scope": "committed-artifact-internal-binding-only",
        "packet_path": EFFICACY_PACKET_PATH.as_posix(),
        "packet_sha256": "BOUND_FROM_REPOSITORY_BYTES",
        "policy_path": EFFICACY_POLICY_PATH.as_posix(),
        "policy_sha256": "BOUND_FROM_REPOSITORY_BYTES",
    },
    "evidence_status": {
        "real_model_study_result": "not_provided",
        "qualifying_external_pilot": "not_provided",
        "independent_empirical_review": "not_provided",
        "frozen_confirmatory_benchmark": "not_provided",
    },
    "authorized_claims": [
        "bounded-engineering-qualification",
        "committed-deterministic-fixture-artifact-validation",
    ],
    "prohibited_claims": [
        "empirical-effectiveness",
        "external-validity",
        "population-generalization",
        "production-control-effectiveness",
        "provider-quality",
        "safety",
        "compliance",
        "deployment-fitness",
    ],
    "canonical_disclosure": CANONICAL_DISCLOSURE,
}

DISCLOSURE_FILES = (
    Path("README.md"),
    Path("CHANGELOG.md"),
    Path("SECURITY.md"),
    Path("docs/release_pypi.md"),
    Path("docs/release_notes/v0.7.0.md"),
)
ABSENT_EMPIRICAL_PATHS = (
    Path("evidence/empirical/real-model-study"),
    Path("evidence/empirical/external-pilot"),
    Path("study/registration/frozen-non-grid-benchmark.json"),
    Path("study/registration/frozen-non-grid-benchmark-statistical-method-review.json"),
    Path("src/agent_assure/release_trust/v0_7_0/frozen-non-grid-benchmark.json"),
    Path(
        "src/agent_assure/release_trust/v0_7_0/"
        "frozen-non-grid-benchmark-statistical-method-review.json"
    ),
)
FORBIDDEN_PUBLICATION_PHRASES = (
    "all empirical and release gates passing",
    "must pass control-efficacy, empirical-readiness",
    "missing empirical or efficacy evidence fails closed",
    "until the empirical publish gate passes",
    "independent evidence-review requirements remain unchanged",
    "the publish gate verifies every file in one closed, bounded, link-free pilot bundle",
    "permanently ineligible for later exact-candidate release gates",
    "hardened the publish checkpoint so bare pilot metadata cannot pass",
    "an explicit required publication target",
    "the real-model-study bundle remains a separate release prerequisite",
    "still-unmet external evidence checkpoint",
    "the publish-gate invocation is",
    "## release-gate boundary",
    "the make release path supplies its `expected_release` explicitly",
    "the public pypi/github release line is v0.7.0",
    "the published github/pypi release line is v0.7.0",
    "v0.7.0 is the current package",
    "current beta package",
    "current released writer schema snapshot: `schemas/v0.6.6/`",
    "contains the released writer snapshot emitted by package v0.7.0",
)


class DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_profile(path: Path) -> dict[str, Any]:
    file_stat = path.lstat()
    if stat.S_ISLNK(file_stat.st_mode):
        raise ValueError("publication claim profile must not be a symbolic link")
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError("publication claim profile must be a regular file")
    if file_stat.st_size > MAX_PROFILE_BYTES:
        raise ValueError("publication claim profile exceeds the maximum size")
    with path.open("rb") as handle:
        data = handle.read(MAX_PROFILE_BYTES + 1)
    if len(data) > MAX_PROFILE_BYTES:
        raise ValueError("publication claim profile exceeds the maximum size")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("publication claim profile is not UTF-8") from exc
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, DuplicateKeyError) as exc:
        raise ValueError(f"publication claim profile is invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("publication claim profile must be a JSON object")
    return payload


def _sha256_bounded_regular_file(path: Path, *, label: str) -> str:
    file_stat = path.lstat()
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    if file_stat.st_size > MAX_EFFICACY_BINDING_BYTES:
        raise ValueError(f"{label} exceeds the maximum size")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            total += len(chunk)
            if total > MAX_EFFICACY_BINDING_BYTES:
                raise ValueError(f"{label} exceeds the maximum size")
            digest.update(chunk)
    return digest.hexdigest()


def _efficacy_project_versions(path: Path) -> tuple[str, ...]:
    file_stat = path.lstat()
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise ValueError("release efficacy artifact must be a regular non-symbolic-link file")
    if file_stat.st_size > MAX_EFFICACY_BINDING_BYTES:
        raise ValueError("release efficacy artifact exceeds the maximum size")
    with path.open("rb") as handle:
        data = handle.read(MAX_EFFICACY_BINDING_BYTES + 1)
    if len(data) > MAX_EFFICACY_BINDING_BYTES:
        raise ValueError("release efficacy artifact exceeds the maximum size")
    try:
        payload = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, DuplicateKeyError) as exc:
        raise ValueError("release efficacy artifact is invalid JSON") from exc
    versions: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            if value.get("name") == "agent-assure" and "version" in value:
                version = value["version"]
                if not isinstance(version, str):
                    raise ValueError("release efficacy agent-assure version must be a string")
                versions.append(version)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(payload)
    if not versions:
        raise ValueError("release efficacy artifact has no agent-assure component version")
    return tuple(versions)


def expected_profile(root: Path) -> dict[str, Any]:
    expected = deepcopy(EXPECTED_PROFILE)
    evidence = expected["control_efficacy_evidence"]
    if not isinstance(evidence, dict):
        raise AssertionError("invalid expected control-efficacy evidence contract")
    evidence["packet_sha256"] = _sha256_bounded_regular_file(
        root / EFFICACY_PACKET_PATH,
        label="release control-efficacy packet",
    )
    evidence["policy_sha256"] = _sha256_bounded_regular_file(
        root / EFFICACY_POLICY_PATH,
        label="release control-efficacy policy",
    )
    return expected


def _project_version(root: Path) -> str:
    try:
        payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        version = payload["project"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("could not read the project version") from exc
    if not isinstance(version, str):
        raise ValueError("project version must be a string")
    return version


def _public_markdown_files(root: Path) -> tuple[Path, ...]:
    candidates = [*root.glob("*.md")]
    for directory in (root / "docs", root / "paper"):
        if directory.is_dir():
            candidates.extend(directory.rglob("*.md"))
    return tuple(sorted({path for path in candidates if path.is_file()}))


def check_release_claim_profile(root: Path, *, expected_release: str) -> list[str]:
    failures: list[str] = []
    release_is_valid = RELEASE_PATTERN.fullmatch(expected_release) is not None
    if not release_is_valid:
        failures.append("expected release must be 0.7.0 or a canonical 0.7.0rcN candidate")
    try:
        project_version = _project_version(root)
    except ValueError as exc:
        failures.append(str(exc))
    else:
        if release_is_valid and project_version != expected_release:
            failures.append(
                f"project version {project_version!r} does not match expected release "
                f"{expected_release!r}"
            )

    if release_is_valid:
        for relative_path in EFFICACY_VERSION_BEARING_JSON_PATHS:
            try:
                artifact_versions = _efficacy_project_versions(root / relative_path)
            except (OSError, ValueError) as exc:
                failures.append(f"{relative_path.as_posix()}: {exc}")
                continue
            stale_versions = sorted(
                {version for version in artifact_versions if version != expected_release}
            )
            if stale_versions:
                failures.append(
                    f"{relative_path.as_posix()} records stale agent-assure versions "
                    f"{stale_versions!r}, expected {expected_release!r}"
                )

    profile_path = root / PROFILE_PATH.relative_to(ROOT)
    try:
        profile = _load_profile(profile_path)
    except (OSError, ValueError) as exc:
        failures.append(str(exc))
    else:
        try:
            expected = expected_profile(root)
        except (OSError, ValueError) as exc:
            failures.append(str(exc))
        else:
            if profile != expected:
                failures.append(
                    "publication claim profile does not exactly match bounded-non-empirical/v1"
                )

    for relative_path in ABSENT_EMPIRICAL_PATHS:
        if (root / relative_path).exists() or (root / relative_path).is_symlink():
            failures.append(
                f"bounded v0.7.0 profile requires empirical trust input to be absent: "
                f"{relative_path.as_posix()}"
            )

    for relative_path in DISCLOSURE_FILES:
        path = root / relative_path
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"could not read release disclosure surface: {relative_path}")
            continue
        if text.count(CANONICAL_DISCLOSURE) != 1:
            failures.append(
                f"{relative_path.as_posix()} must contain the canonical bounded-release "
                "disclosure exactly once"
            )
    for path in _public_markdown_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            failures.append(
                f"could not read public claim surface: {path.relative_to(root).as_posix()}"
            )
            continue
        normalized = " ".join(text.casefold().split())
        for phrase in FORBIDDEN_PUBLICATION_PHRASES:
            if phrase in normalized:
                failures.append(
                    f"{path.relative_to(root).as_posix()} retains contradictory "
                    "publication language: "
                    f"{phrase!r}"
                )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the committed v0.7.0 bounded publication claim profile."
    )
    parser.add_argument("--expected-release", required=True)
    args = parser.parse_args(argv)
    failures = check_release_claim_profile(ROOT, expected_release=args.expected_release)
    if failures:
        for failure in failures:
            print(f"release-claim-profile: {failure}", file=sys.stderr)
        return 1
    print(
        "release-claim-profile: ok "
        f"(bounded-non-empirical/v1, expected-release={args.expected_release})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
