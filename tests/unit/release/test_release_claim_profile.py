from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

import scripts.check_release_claim_profile as claim_profile


def _write_repository(
    root: Path,
    *,
    version: str = "0.7.0",
    profile: dict[str, object] | None = None,
) -> None:
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "agent-assure"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    packet_path = root / claim_profile.EFFICACY_PACKET_PATH
    packet_path.parent.mkdir(parents=True, exist_ok=True)
    packet_path.write_bytes(b'{"artifact_kind":"evidence-packet"}\n')
    policy_path = root / claim_profile.EFFICACY_POLICY_PATH
    policy_path.write_text("artifact_kind: controls-mutation-onboarding-config\n", encoding="utf-8")
    version_bearing_artifact = {
        "artifact_kind": "dependency-inventory",
        "components": [{"name": "agent-assure", "type": "library", "version": version}],
    }
    for relative_path in claim_profile.EFFICACY_VERSION_BEARING_JSON_PATHS:
        artifact_path = root / relative_path
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(
            json.dumps(version_bearing_artifact, indent=2) + "\n",
            encoding="utf-8",
        )
    profile_path = root / claim_profile.PROFILE_PATH.relative_to(claim_profile.ROOT)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(
        json.dumps(
            profile if profile is not None else claim_profile.expected_profile(root),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    for relative_path in claim_profile.DISCLOSURE_FILES:
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(claim_profile.CANONICAL_DISCLOSURE + "\n", encoding="utf-8")


@pytest.mark.parametrize("version", ("0.7.0", "0.7.0rc1", "0.7.0rc12"))
def test_bounded_profile_accepts_stable_and_release_candidates(
    tmp_path: Path,
    version: str,
) -> None:
    _write_repository(tmp_path, version=version)

    assert claim_profile.check_release_claim_profile(tmp_path, expected_release=version) == []


def test_bounded_profile_rejects_wrong_or_mismatched_release(tmp_path: Path) -> None:
    _write_repository(tmp_path)

    assert claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.8.0",
    ) == ["expected release must be 0.7.0 or a canonical 0.7.0rcN candidate"]
    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0rc1",
    )
    assert failures[0] == "project version '0.7.0' does not match expected release '0.7.0rc1'"
    assert len(failures) == 1 + len(claim_profile.EFFICACY_VERSION_BEARING_JSON_PATHS)
    assert all(
        "records stale agent-assure versions ['0.7.0'], expected '0.7.0rc1'" in failure
        for failure in failures[1:]
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("profile_id", "empirical/v1"),
        ("control_efficacy_basis", "production"),
        ("evidence_status", {"real_model_study_result": "provided"}),
        ("authorized_claims", ["empirical-effectiveness"]),
        ("unexpected", True),
    ),
)
def test_bounded_profile_rejects_any_contract_change(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    _write_repository(tmp_path)
    profile = deepcopy(claim_profile.expected_profile(tmp_path))
    profile[field] = replacement
    _write_repository(tmp_path, profile=profile)

    assert claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    ) == ["publication claim profile does not exactly match bounded-non-empirical/v1"]


def test_bounded_profile_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    path = tmp_path / claim_profile.PROFILE_PATH.relative_to(claim_profile.ROOT)
    path.write_text('{"profile_id":"a","profile_id":"b"}\n', encoding="utf-8")

    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    )

    assert len(failures) == 1
    assert "duplicate JSON key: profile_id" in failures[0]


def test_bounded_profile_rejects_oversized_profile_before_parsing(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    path = tmp_path / claim_profile.PROFILE_PATH.relative_to(claim_profile.ROOT)
    path.write_bytes(b"{" + b" " * claim_profile.MAX_PROFILE_BYTES)

    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    )

    assert failures == ["publication claim profile exceeds the maximum size"]


def test_bounded_profile_rejects_non_regular_profile(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    path = tmp_path / claim_profile.PROFILE_PATH.relative_to(claim_profile.ROOT)
    path.unlink()
    path.mkdir()

    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    )

    assert failures == ["publication claim profile must be a regular file"]


def test_bounded_profile_rejects_symlinked_profile(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    path = tmp_path / claim_profile.PROFILE_PATH.relative_to(claim_profile.ROOT)
    target = path.with_name("profile-target.json")
    target.write_bytes(path.read_bytes())
    path.unlink()
    try:
        path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    )

    assert failures == ["publication claim profile must not be a symbolic link"]


def test_bounded_profile_requires_every_disclosure_and_absent_empirical_inputs(
    tmp_path: Path,
) -> None:
    _write_repository(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text("missing disclosure\n", encoding="utf-8")
    empirical_path = tmp_path / claim_profile.ABSENT_EMPIRICAL_PATHS[0]
    empirical_path.mkdir(parents=True)

    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    )

    assert any("README.md must contain" in failure for failure in failures)
    assert any("evidence/empirical/real-model-study" in failure for failure in failures)


def test_bounded_profile_binds_committed_packet_and_policy_bytes(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    packet_path = tmp_path / claim_profile.EFFICACY_PACKET_PATH
    packet_path.write_bytes(packet_path.read_bytes() + b" ")

    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    )

    assert failures == ["publication claim profile does not exactly match bounded-non-empirical/v1"]


def test_bounded_profile_rejects_stale_project_dependency_inventory(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    inventory_path = tmp_path / claim_profile.EFFICACY_DEPENDENCY_INVENTORY_PATHS[0]
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["components"][0]["version"] = "0.6.2"
    inventory_path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")

    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    )

    assert failures == [
        "evidence/synthetic/release-control-efficacy/dependency-inventory.json "
        "records stale agent-assure versions ['0.6.2'], expected '0.7.0'"
    ]


def test_bounded_profile_rejects_contradictory_publication_language(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    security = tmp_path / "SECURITY.md"
    security.write_text(
        claim_profile.CANONICAL_DISCLOSURE
        + "\nEvery release is conditional on all empirical and\nrelease gates passing.\n",
        encoding="utf-8",
    )
    threat_model = tmp_path / "docs" / "threat_model.md"
    threat_model.write_text(
        "The publish gate verifies every file in one closed, bounded,\nlink-free pilot bundle.\n",
        encoding="utf-8",
    )

    failures = claim_profile.check_release_claim_profile(
        tmp_path,
        expected_release="0.7.0",
    )

    assert any(
        "SECURITY.md retains contradictory publication language" in failure for failure in failures
    )
    assert any(
        "docs/threat_model.md retains contradictory publication language" in failure
        for failure in failures
    )
