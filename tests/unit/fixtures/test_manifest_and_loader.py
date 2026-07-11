from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from agent_assure.authoring.compiler import compile_suite
from agent_assure.fixtures.loader import (
    load_compiled_suite,
    verify_source_digest,
    write_compiled_suite,
)
from agent_assure.fixtures.manifest import build_fixture_manifest, verify_fixture_manifest
from agent_assure.fixtures.resolver import FixturePathError, FixtureResolver
from agent_assure.runner.fixture_runner import load_variant_config, run_suite

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")


def test_fixture_resolver_rejects_escape_segments() -> None:
    resolver = FixtureResolver(SUITE.parent)
    with pytest.raises(FixturePathError):
        resolver.resolve("../outside.json")


def test_fixture_resolver_rejects_absolute_paths() -> None:
    resolver = FixtureResolver(SUITE.parent)
    with pytest.raises(FixturePathError):
        resolver.resolve("/tmp/outside.json")


def test_fixture_manifest_paths_are_posix_normalized() -> None:
    compiled = compile_suite(SUITE)
    manifest = build_fixture_manifest(compiled, SUITE.parent)
    assert manifest.entries
    assert all("\\" not in entry.path for entry in manifest.entries)
    assert all(entry.path.startswith("fixtures/shared/") for entry in manifest.entries)


def test_case_fixtures_can_load_from_non_first_declared_root(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = _write_minimal_suite(tmp_path, ("fixtures/root-a", "fixtures/root-b"))
    _make_fixture_dirs(tmp_path, "fixtures/root-a")
    _write_prior_auth_fixture_triplet(tmp_path, "fixtures/root-b", "case-fixture")
    compiled = compile_suite(suite)
    runset = run_suite(
        compiled,
        load_variant_config(BASELINE),
        tmp_path,
        hmac_key=b"multi-root-test-key-32-byte-value-0000",
    )
    assert runset.runs[0].case_id == "case-001"
    assert runset.runs[0].outcome == "approve"


def test_duplicate_case_fixture_across_roots_is_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = _write_minimal_suite(tmp_path, ("fixtures/root-a", "fixtures/root-b"))
    _write_prior_auth_fixture_triplet(tmp_path, "fixtures/root-a", "case-fixture")
    _write_prior_auth_fixture_triplet(tmp_path, "fixtures/root-b", "case-fixture")
    compiled = compile_suite(suite)
    with pytest.raises(ValueError, match="ambiguous across fixture roots"):
        build_fixture_manifest(compiled, tmp_path)


def test_missing_fixture_subdir_is_rejected_at_manifest_time(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = _write_minimal_suite(tmp_path, ("fixtures/root-a",))
    (tmp_path / "fixtures" / "root-a" / "requests").mkdir(parents=True)
    compiled = compile_suite(suite)
    with pytest.raises(FileNotFoundError, match="missing required subdirectory"):
        build_fixture_manifest(compiled, tmp_path)


def test_manifest_hashes_crlf_fixture_bytes(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = _write_minimal_suite(tmp_path, ("fixtures/root-a",))
    _write_prior_auth_fixture_triplet(tmp_path, "fixtures/root-a", "case-fixture")
    request = tmp_path / "fixtures" / "root-a" / "requests" / "case-fixture.json"
    raw = b'{\r\n  "case_id": "case-001",\r\n  "member_id": "SYN-MEMBER-001"\r\n}\r\n'
    request.write_bytes(raw)
    manifest = build_fixture_manifest(compile_suite(suite), tmp_path)
    entry = next(
        item for item in manifest.entries if item.path.endswith("/requests/case-fixture.json")
    )
    assert entry.sha256 == hashlib.sha256(raw).hexdigest()


def test_fixture_manifest_rejects_symlinked_files(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = _write_minimal_suite(tmp_path, ("fixtures/root-a",))
    _write_prior_auth_fixture_triplet(tmp_path, "fixtures/root-a", "case-fixture")
    outside = tmp_path / "outside.json"
    outside.write_text('{"case_id": "outside"}', encoding="utf-8")
    request = tmp_path / "fixtures" / "root-a" / "requests" / "case-fixture.json"
    request.unlink()
    try:
        request.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is not available in this environment")

    with pytest.raises(ValueError, match="refuses symlinked path"):
        build_fixture_manifest(compile_suite(suite), tmp_path)


def test_fixture_manifest_verification_detects_drift(tmp_path) -> None:  # type: ignore[no-untyped-def]
    compiled = compile_suite(SUITE)
    manifest = build_fixture_manifest(compiled, SUITE.parent)
    fixture_root = tmp_path / "suite"
    fixture_root.mkdir()
    shutil.copytree(SUITE.parent / "fixtures", fixture_root / "fixtures")
    changed = fixture_root / "fixtures" / "shared" / "requests" / "straightforward-approval.json"
    changed.write_text('{"case_id": "changed", "member_id": "SYN-MEMBER-001"}', encoding="utf-8")
    with pytest.raises(ValueError):
        verify_fixture_manifest(manifest, compiled, fixture_root)


def test_compiled_suite_loader_and_source_digest_verification(tmp_path) -> None:  # type: ignore[no-untyped-def]
    compiled = compile_suite(SUITE)
    out = tmp_path / "compiled.json"
    write_compiled_suite(compiled, out)
    loaded = load_compiled_suite(out)
    assert loaded == compiled
    verify_source_digest(loaded, SUITE)


def test_compiled_suite_loader_checks_expected_digest(tmp_path) -> None:  # type: ignore[no-untyped-def]
    compiled = compile_suite(SUITE)
    out = tmp_path / "compiled.json"
    out.write_text(json.dumps(compiled.model_dump(mode="json")), encoding="utf-8")
    with pytest.raises(ValueError, match="compiled suite digest mismatch"):
        load_compiled_suite(out, expected_digest="0" * 64)


def _write_minimal_suite(tmp_path: Path, fixture_roots: tuple[str, ...]) -> Path:
    roots = "\n".join(f"    - {root}" for root in fixture_roots)
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        f"""
suite_id: multi-root-demo
suite_version: 0.1.0
defaults:
  execution_mode: fixture
  runner_id: prior_auth.synthetic
  fixture_roots:
{roots}
cases:
  - case_id: case-001
    title: Multi-root case
    fixture_id: case-fixture
    expectation:
      expected_recommendation: approve
""".lstrip(),
        encoding="utf-8",
    )
    return suite


def _make_fixture_dirs(tmp_path: Path, root: str) -> None:
    for subdir in ("requests", "model_outputs", "tool_outputs"):
        (tmp_path / root / subdir).mkdir(parents=True, exist_ok=True)


def _write_prior_auth_fixture_triplet(tmp_path: Path, root: str, fixture_id: str) -> None:
    _make_fixture_dirs(tmp_path, root)
    (tmp_path / root / "requests" / f"{fixture_id}.json").write_text(
        json.dumps({"case_id": "case-001", "member_id": "SYN-MEMBER-001"}),
        encoding="utf-8",
    )
    (tmp_path / root / "model_outputs" / f"{fixture_id}.json").write_text(
        json.dumps(
            {
                "human_review_performed": False,
                "human_review_required": False,
                "model": "approved-fixture-model-v1",
                "outcome": "approve",
                "provider": "approved-prior-auth-model",
                "recommendation": "approve",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / root / "tool_outputs" / f"{fixture_id}.json").write_text(
        json.dumps(
            {
                "evidence": [],
                "tools": ["coverage_policy_lookup"],
            }
        ),
        encoding="utf-8",
    )
