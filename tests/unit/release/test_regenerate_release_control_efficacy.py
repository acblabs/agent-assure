from __future__ import annotations

import hashlib
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import scripts.check_release_claim_profile as claim_profile
import scripts.regenerate_release_control_efficacy as regenerate


def _write_inventory(root: Path, *, complete: bool) -> None:
    for name in regenerate.PRESERVED_TOP_LEVEL:
        (root / name).write_text(f"{name}\n", encoding="utf-8")
    if not complete:
        return
    directory_names = {"control-efficacy", "evaluation", "mutation-results"}
    for name in regenerate.GENERATED_TOP_LEVEL:
        path = root / name
        if name in directory_names:
            path.mkdir()
        else:
            path.write_text(f"{name}\n", encoding="utf-8")


def test_render_config_replaces_exactly_one_version() -> None:
    source = 'artifact_kind: controls-mutation-onboarding-config\npackage_version: "0.7.0"\n'

    assert regenerate._render_config(source, expected_release="0.7.0rc1") == (
        'artifact_kind: controls-mutation-onboarding-config\npackage_version: "0.7.0rc1"\n'
    )


@pytest.mark.parametrize(
    "source",
    (
        "artifact_kind: controls-mutation-onboarding-config\n",
        'package_version: "0.7.0"\npackage_version: "0.7.0rc1"\n',
    ),
)
def test_render_config_rejects_missing_or_duplicate_version(source: str) -> None:
    with pytest.raises(ValueError, match="package_version exactly once"):
        regenerate._render_config(source, expected_release="0.7.0")


def test_inventory_rejects_unknown_entries(tmp_path: Path) -> None:
    _write_inventory(tmp_path, complete=False)
    (tmp_path / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected top-level entries"):
        regenerate._validate_inventory(tmp_path, require_complete=False)


def test_inventory_requires_complete_generated_output_set(tmp_path: Path) -> None:
    _write_inventory(tmp_path, complete=False)

    with pytest.raises(ValueError, match="generated outputs are missing"):
        regenerate._validate_inventory(tmp_path)


def test_inventory_accepts_complete_regular_tree(tmp_path: Path) -> None:
    _write_inventory(tmp_path, complete=True)

    regenerate._validate_inventory(tmp_path)


def test_inventory_rejects_symbolic_link(tmp_path: Path) -> None:
    _write_inventory(tmp_path, complete=True)
    packet = tmp_path / "evidence-packet.json"
    target = tmp_path.parent / f"{tmp_path.name}-packet-target.json"
    target.write_text(packet.read_text(encoding="utf-8"), encoding="utf-8")
    packet.unlink()
    try:
        packet.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    with pytest.raises(ValueError, match="link or reparse point"):
        regenerate._validate_inventory(tmp_path)


def test_refresh_profile_digests_changes_only_bound_hashes(tmp_path: Path) -> None:
    packet = tmp_path / "evidence-packet.json"
    packet.write_bytes(b'{"artifact_kind":"evidence-packet"}\n')
    policy = tmp_path / "controls-mutation.yaml"
    policy.write_text("artifact_kind: controls-mutation-onboarding-config\n", encoding="utf-8")
    profile_path = tmp_path / "publication-claim-profile.json"
    profile_path.write_text(
        json.dumps(deepcopy(claim_profile.EXPECTED_PROFILE), indent=2) + "\n",
        encoding="utf-8",
    )

    regenerate._refresh_profile_digests(
        profile_path,
        packet_path=packet,
        policy_path=policy,
    )

    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    evidence = profile["control_efficacy_evidence"]
    assert evidence["packet_sha256"] == hashlib.sha256(packet.read_bytes()).hexdigest()
    assert evidence["policy_sha256"] == hashlib.sha256(policy.read_bytes()).hexdigest()
    normalized = deepcopy(profile)
    normalized_evidence = normalized["control_efficacy_evidence"]
    normalized_evidence["packet_sha256"] = "BOUND_FROM_REPOSITORY_BYTES"
    normalized_evidence["policy_sha256"] = "BOUND_FROM_REPOSITORY_BYTES"
    assert normalized == claim_profile.EXPECTED_PROFILE


def test_scoped_patch_includes_recreated_generated_files(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    generated = root / regenerate.EVIDENCE_RELATIVE / "evidence-packet.json"
    profile = root / regenerate.PROFILE_RELATIVE
    generated.parent.mkdir(parents=True)
    profile.parent.mkdir(parents=True)
    generated.write_text("old packet\n", encoding="utf-8")
    profile.write_text("profile\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(root), "init"), check=True, capture_output=True)
    subprocess.run(
        ("git", "-C", str(root), "config", "user.name", "Regeneration Test"),
        check=True,
    )
    subprocess.run(
        ("git", "-C", str(root), "config", "user.email", "regeneration@example.invalid"),
        check=True,
    )
    subprocess.run(("git", "-C", str(root), "add", "--all"), check=True)
    subprocess.run(
        ("git", "-C", str(root), "commit", "-m", "baseline"),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ("git", "-C", str(root), "rm", generated.relative_to(root).as_posix()),
        check=True,
        capture_output=True,
    )
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text("new packet\n", encoding="utf-8")
    runtime_lock = root / regenerate.RUNTIME_LOCK_RELATIVE
    runtime_lock.parent.mkdir(parents=True, exist_ok=True)
    runtime_lock.write_bytes(b"\0")

    patch = regenerate._build_scoped_patch(root)

    assert b"-old packet" in patch
    assert b"+new packet" in patch
    assert b".agent-assure-mutation.lock" not in patch
    assert not runtime_lock.exists()


def test_make_target_owns_fixed_regeneration_command() -> None:
    makefile = (regenerate.ROOT / "Makefile").read_text(encoding="utf-8")

    assert "release-control-efficacy-regenerate:" in makefile
    assert (
        'scripts/regenerate_release_control_efficacy.py --expected-release "$(EXPECTED_RELEASE)" '
        "--replace-generated"
    ) in makefile
