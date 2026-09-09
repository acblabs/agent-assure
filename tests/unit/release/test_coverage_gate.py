from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml

from scripts.check_coverage_gate import main

ROOT = Path(__file__).resolve().parents[3]


def test_inventory_requires_exact_regular_files(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "coverage"
    artifact_dir.mkdir()
    (artifact_dir / ".coverage.a").write_bytes(b"coverage")

    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(artifact_dir),
                "--expected",
                ".coverage.a",
            ]
        )
        == 0
    )

    (artifact_dir / ".coverage.unexpected").write_bytes(b"coverage")
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(artifact_dir),
                "--expected",
                ".coverage.a",
            ]
        )
        == 1
    )


def test_inventory_fails_closed_on_missing_directory(tmp_path: Path) -> None:
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(tmp_path / "missing"),
                "--expected",
                ".coverage.a",
            ]
        )
        == 2
    )


def test_branch_gate_uses_pure_branch_percentage(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps({"totals": {"covered_branches": 65, "num_branches": 100}}),
        encoding="utf-8",
    )

    assert main(["branches", "--report", str(report), "--fail-under", "65"]) == 0
    assert main(["branches", "--report", str(report), "--fail-under", "65.01"]) == 1


def test_branch_gate_rejects_malformed_or_inconsistent_counts(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    for payload in (
        {},
        {"totals": {"covered_branches": True, "num_branches": 100}},
        {"totals": {"covered_branches": 101, "num_branches": 100}},
        {"totals": {"covered_branches": 0, "num_branches": 0}},
    ):
        report.write_text(json.dumps(payload), encoding="utf-8")
        assert main(["branches", "--report", str(report), "--fail-under", "65"]) == 2


def test_ci_coverage_gate_is_complete_branch_enabled_and_fail_closed() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    shards = jobs["coverage-shards"]
    expected_paths = {
        "unit-a": (
            "tests/unit/adapters tests/unit/authoring tests/unit/canonical "
            "tests/unit/compare tests/unit/controls tests/unit/demo tests/unit/docs "
            "tests/unit/evaluation tests/unit/examples tests/unit/fixtures "
            "tests/unit/graph tests/unit/mutation"
        ),
        "unit-b1": (
            "tests/unit/policies tests/unit/privacy tests/unit/rag "
            "tests/unit/release tests/unit/reporting"
        ),
        "unit-b2": (
            "tests/unit/runner tests/unit/schema tests/unit/statistics "
            "tests/unit/streaming tests/unit/study tests/unit/telemetry tests/unit/usage"
        ),
        "unit-top": "tests/unit/test_*.py",
        "integration": "tests/integration",
    }
    matrix = shards["strategy"]["matrix"]["include"]
    assert {entry["shard"]: entry["test_paths"] for entry in matrix} == expected_paths
    assert shards["strategy"]["fail-fast"] is False
    assert shards["env"]["COVERAGE_FILE"] == ".coverage.${{ matrix.shard }}"
    assert all("continue-on-error" not in step for step in shards["steps"])

    run_step = next(
        step for step in shards["steps"] if step.get("name") == "Run branch-coverage shard"
    )
    assert "--cov=agent_assure --cov-branch --cov-report=" in run_step["run"]
    upload = next(
        step
        for step in shards["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    )
    assert upload["uses"].endswith("@ea165f8d65b6e75b540449e92b4886f43607fa02")
    assert upload["if"] == "${{ always() }}"
    assert upload["with"]["include-hidden-files"] is True
    assert upload["with"]["if-no-files-found"] == "error"

    gate = jobs["coverage-gate"]
    assert gate["needs"] == "coverage-shards"
    assert gate["if"] == "${{ always() }}"
    assert all("continue-on-error" not in step for step in gate["steps"])
    require = gate["steps"][0]
    assert require["if"] == "${{ needs.coverage-shards.result != 'success' }}"
    assert require["run"] == "exit 1"
    download = next(
        step
        for step in gate["steps"]
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    )
    assert download["uses"].endswith("@d3f86a106a0bac45b974a628896c90dbdf5c8093")
    assert download["with"] == {
        "pattern": "coverage-*",
        "path": ".coverage-data",
        "merge-multiple": True,
    }
    gate_commands = "\n".join(str(step.get("run", "")) for step in gate["steps"])
    for name in expected_paths:
        assert f"--expected .coverage.{name}" in gate_commands
    assert "python -m coverage combine --keep .coverage-data" in gate_commands
    assert "python -m coverage report" in gate_commands
    assert "--fail-under 65" in gate_commands

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["coverage"]["run"] == {
        "branch": True,
        "source": ["agent_assure"],
        "relative_files": True,
    }
    assert project["tool"]["coverage"]["report"]["fail_under"] == 80
