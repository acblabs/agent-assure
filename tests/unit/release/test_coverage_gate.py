from __future__ import annotations

import json
import re
import shutil
import tomllib
from pathlib import Path

import coverage
import pytest
import yaml
from coverage import CoverageData

import scripts.check_coverage_gate as coverage_gate
from scripts.check_coverage_gate import main

ROOT = Path(__file__).resolve().parents[3]


def _write_coverage_database(
    path: Path,
    *,
    filename: str | None = None,
    branch: bool = True,
) -> None:
    filenames = (
        {filename}
        if filename is not None
        else {
            source_path.relative_to(ROOT).as_posix()
            for source_path in (ROOT / "src" / "agent_assure").rglob("*.py")
        }
    )
    data = CoverageData(basename=str(path))
    if branch:
        data.add_arcs({source_filename: {(-1, 1), (1, -1)} for source_filename in filenames})
    else:
        data.add_lines({source_filename: {1} for source_filename in filenames})
    data.write()


def _branch_report(
    files: dict[str, tuple[int, int]],
    *,
    branch_coverage: bool = True,
) -> dict[str, object]:
    complete_files = {
        source_path.relative_to(ROOT).as_posix(): (0, 0)
        for source_path in (ROOT / "src" / "agent_assure").rglob("*.py")
    }
    for raw_path in files:
        normalized_path = raw_path.replace("\\", "/")
        if raw_path != normalized_path and normalized_path not in files:
            complete_files.pop(normalized_path, None)
    complete_files.update(files)
    return {
        "meta": {
            "branch_coverage": branch_coverage,
            "format": 3,
            "version": coverage.__version__,
        },
        "files": {
            path: {
                "summary": {
                    "covered_branches": covered,
                    "num_branches": total,
                }
            }
            for path, (covered, total) in complete_files.items()
        },
        "totals": {
            "covered_branches": sum(covered for covered, _ in complete_files.values()),
            "num_branches": sum(total for _, total in complete_files.values()),
        },
    }


def test_inventory_requires_exact_regular_files(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "coverage"
    artifact_dir.mkdir()
    _write_coverage_database(artifact_dir / ".coverage.a")

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


def test_inventory_rejects_unreadable_nonbranch_and_empty_databases(
    tmp_path: Path,
) -> None:
    corrupt_dir = tmp_path / "corrupt"
    corrupt_dir.mkdir()
    (corrupt_dir / ".coverage.a").write_bytes(b"not sqlite")
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(corrupt_dir),
                "--expected",
                ".coverage.a",
            ]
        )
        == 2
    )

    nonbranch_dir = tmp_path / "nonbranch"
    nonbranch_dir.mkdir()
    _write_coverage_database(nonbranch_dir / ".coverage.a", branch=False)
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(nonbranch_dir),
                "--expected",
                ".coverage.a",
            ]
        )
        == 2
    )

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    empty_data = CoverageData(basename=str(empty_dir / ".coverage.a"))
    empty_data.add_arcs({"src/agent_assure/example.py": {(-1, 1), (1, -1)}})
    empty_data.write()
    empty_data.purge_files({"src/agent_assure/example.py"})
    empty_data.write()
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(empty_dir),
                "--expected",
                ".coverage.a",
            ]
        )
        == 2
    )

    partial_dir = tmp_path / "partial"
    partial_dir.mkdir()
    _write_coverage_database(
        partial_dir / ".coverage.a",
        filename="src/agent_assure/example.py",
    )
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(partial_dir),
                "--expected",
                ".coverage.a",
            ]
        )
        == 2
    )


def test_inventory_enforces_the_database_byte_limit_without_a_large_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert coverage_gate.MAX_COVERAGE_DATABASE_BYTES == 64 * 1024 * 1024
    artifact_dir = tmp_path / "coverage"
    artifact_dir.mkdir()
    database = artifact_dir / ".coverage.a"
    _write_coverage_database(database)
    database_size = database.stat().st_size

    monkeypatch.setattr(coverage_gate, "MAX_COVERAGE_DATABASE_BYTES", database_size)
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

    monkeypatch.setattr(coverage_gate, "MAX_COVERAGE_DATABASE_BYTES", database_size - 1)
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
        == 2
    )


def test_inventory_rejects_a_database_that_changes_during_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_dir = tmp_path / "coverage"
    artifact_dir.mkdir()
    database = artifact_dir / ".coverage.a"
    _write_coverage_database(database)
    original_digest = coverage_gate._coverage_database_digest
    digest_calls = 0

    def digest_with_second_read_change(path: Path) -> tuple[str, int]:
        nonlocal digest_calls
        digest_calls += 1
        digest, size = original_digest(path)
        if digest_calls == 2:
            return "0" * 64, size
        return digest, size

    monkeypatch.setattr(coverage_gate, "_coverage_database_digest", digest_with_second_read_change)

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
        == 2
    )
    assert digest_calls == 2


def test_inventory_rejects_symlinks_but_allows_equivalent_shard_data(
    tmp_path: Path,
) -> None:
    duplicate_dir = tmp_path / "duplicates"
    duplicate_dir.mkdir()
    _write_coverage_database(duplicate_dir / ".coverage.a")
    shutil.copyfile(duplicate_dir / ".coverage.a", duplicate_dir / ".coverage.b")
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(duplicate_dir),
                "--expected",
                ".coverage.a",
                "--expected",
                ".coverage.b",
            ]
        )
        == 0
    )

    symlink_dir = tmp_path / "symlink"
    symlink_dir.mkdir()
    target = tmp_path / "outside.coverage"
    _write_coverage_database(target)
    try:
        (symlink_dir / ".coverage.a").symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(symlink_dir),
                "--expected",
                ".coverage.a",
            ]
        )
        == 2
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


def test_inventory_rejects_symlinked_root_and_invalid_expected_names(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "coverage"
    artifact_dir.mkdir()
    _write_coverage_database(artifact_dir / ".coverage.a")

    for expected_name in (
        "../.coverage.a",
        ".coverage.",
        ".coverage." + ("a" * 129),
    ):
        assert (
            main(
                [
                    "inventory",
                    "--artifact-dir",
                    str(artifact_dir),
                    "--expected",
                    expected_name,
                ]
            )
            == 2
        )
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(artifact_dir),
                "--expected",
                ".coverage.a",
                "--expected",
                ".coverage.a",
            ]
        )
        == 2
    )

    symlink_root = tmp_path / "coverage-link"
    try:
        symlink_root.symlink_to(artifact_dir, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    assert (
        main(
            [
                "inventory",
                "--artifact-dir",
                str(symlink_root),
                "--expected",
                ".coverage.a",
            ]
        )
        == 2
    )


def test_branch_gate_uses_pure_branch_percentage(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(_branch_report({"src/agent_assure/ci.py": (65, 100)})),
        encoding="utf-8",
    )

    assert main(["branches", "--report", str(report), "--fail-under", "65"]) == 0
    assert main(["branches", "--report", str(report), "--fail-under", "65.01"]) == 1


def test_branch_gate_enforces_aggregate_critical_directory_floors(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(
            _branch_report(
                {
                    "src/agent_assure/live/adapters.py": (8, 10),
                    "src\\agent_assure\\live\\runner.py": (7, 10),
                }
            )
        ),
        encoding="utf-8",
    )

    arguments = [
        "branches",
        "--report",
        str(report),
        "--fail-under",
        "70",
        "--critical-prefix",
        "src/agent_assure/live/=75",
    ]
    assert main(arguments) == 0
    arguments[-1] = "src/agent_assure/live/=75.01"
    assert main(arguments) == 1


def test_branch_gate_fails_closed_on_invalid_or_uncovered_critical_prefix(
    tmp_path: Path,
) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(_branch_report({"src/agent_assure/ci.py": (75, 100)})),
        encoding="utf-8",
    )

    for spec in (
        "../live/=75",
        "C:/agent_assure/live/=75",
        "src/agent_assure/live=75",
        "src/agent_assure/live/=not-a-number",
        "src/agent_assure/live/=75",
    ):
        assert (
            main(
                [
                    "branches",
                    "--report",
                    str(report),
                    "--fail-under",
                    "70",
                    "--critical-prefix",
                    spec,
                ]
            )
            == 2
        )


def test_branch_gate_rejects_malformed_or_inconsistent_counts(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    valid_meta = _branch_report({"src/agent_assure/ci.py": (65, 100)})["meta"]
    for payload in (
        {},
        {
            "meta": valid_meta,
            "files": {
                "src/agent_assure/ci.py": {"summary": {"covered_branches": 65, "num_branches": 100}}
            },
            "totals": {"covered_branches": True, "num_branches": 100},
        },
        {
            "meta": valid_meta,
            "files": {
                "src/agent_assure/ci.py": {
                    "summary": {"covered_branches": 101, "num_branches": 100}
                }
            },
            "totals": {"covered_branches": 101, "num_branches": 100},
        },
        {
            "meta": valid_meta,
            "files": {
                "src/agent_assure/ci.py": {"summary": {"covered_branches": 0, "num_branches": 0}}
            },
            "totals": {"covered_branches": 0, "num_branches": 0},
        },
    ):
        report.write_text(json.dumps(payload), encoding="utf-8")
        assert main(["branches", "--report", str(report), "--fail-under", "65"]) == 2


def test_branch_gate_rejects_incompatible_metadata_and_unreconciled_totals(
    tmp_path: Path,
) -> None:
    report = tmp_path / "coverage.json"
    nonbranch = _branch_report(
        {"src/agent_assure/ci.py": (65, 100)},
        branch_coverage=False,
    )
    unreconciled = _branch_report({"src/agent_assure/ci.py": (65, 100)})
    unreconciled["totals"] = {"covered_branches": 66, "num_branches": 100}
    wrong_version = _branch_report({"src/agent_assure/ci.py": (65, 100)})
    assert isinstance(wrong_version["meta"], dict)
    wrong_version["meta"]["version"] = "0.0"
    partial_inventory = _branch_report({"src/agent_assure/ci.py": (65, 100)})
    assert isinstance(partial_inventory["files"], dict)
    partial_inventory["files"].pop("src/agent_assure/live/runner.py")

    for payload in (nonbranch, unreconciled, wrong_version, partial_inventory):
        report.write_text(json.dumps(payload), encoding="utf-8")
        assert main(["branches", "--report", str(report), "--fail-under", "65"]) == 2


def test_branch_gate_rejects_unsafe_malformed_or_colliding_file_entries(
    tmp_path: Path,
) -> None:
    report = tmp_path / "coverage.json"
    malformed = _branch_report(
        {
            "src/agent_assure/ci.py": (30, 50),
            "src/agent_assure/artifact_io.py": (35, 50),
        }
    )
    assert isinstance(malformed["files"], dict)
    malformed["files"]["src/agent_assure/artifact_io.py"] = {"summary": "invalid"}

    payloads = (
        _branch_report({"../src/agent_assure/ci.py": (65, 100)}),
        _branch_report({"C:\\src\\agent_assure\\ci.py": (65, 100)}),
        malformed,
        _branch_report(
            {
                "src/agent_assure/ci.py": (30, 50),
                "src\\agent_assure\\ci.py": (35, 50),
            }
        ),
    )
    for payload in payloads:
        report.write_text(json.dumps(payload), encoding="utf-8")
        assert main(["branches", "--report", str(report), "--fail-under", "65"]) == 2


def test_branch_gate_rejects_duplicate_or_excessive_critical_prefixes(
    tmp_path: Path,
) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(_branch_report({"src/agent_assure/live/runner.py": (80, 100)})),
        encoding="utf-8",
    )
    base = ["branches", "--report", str(report), "--fail-under", "70"]
    assert (
        main(
            [
                *base,
                "--critical-prefix",
                "src/agent_assure/live/=70",
                "--critical-prefix",
                "src\\agent_assure\\live\\=70",
            ]
        )
        == 2
    )
    excessive = [
        item
        for index in range(33)
        for item in (
            "--critical-prefix",
            f"src/agent_assure/module_{index}/=0",
        )
    ]
    assert main([*base, *excessive]) == 2


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
    assert shards["runs-on"] == "ubuntu-24.04"
    assert shards["timeout-minutes"] == 180
    assert shards["strategy"]["fail-fast"] is False
    assert shards["env"]["COVERAGE_FILE"] == ".coverage.${{ matrix.shard }}"
    assert all("continue-on-error" not in step for step in shards["steps"])

    def is_collected_test(path: Path) -> bool:
        return path.suffix == ".py" and (
            path.name.startswith("test_") or path.name.endswith("_test.py")
        )

    expected_tests = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "tests").rglob("*.py")
        if is_collected_test(path)
    }
    assignments: dict[str, list[str]] = {}
    for entry in matrix:
        for selector in str(entry["test_paths"]).split():
            if any(character in selector for character in "*?["):
                selected = tuple(ROOT.glob(selector))
            else:
                selected_root = ROOT / selector
                assert selected_root.exists()
                selected = (
                    tuple(selected_root.rglob("*.py"))
                    if selected_root.is_dir()
                    else (selected_root,)
                )
            selected_tests = {path for path in selected if is_collected_test(path)}
            assert selected_tests
            for path in selected_tests:
                relative = path.relative_to(ROOT).as_posix()
                assignments.setdefault(relative, []).append(str(entry["shard"]))
    assert set(assignments) == expected_tests
    assert all(len(shards_for_file) == 1 for shards_for_file in assignments.values())

    checkout = next(
        step
        for step in shards["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    run_step = next(
        step for step in shards["steps"] if step.get("name") == "Run branch-coverage shard"
    )
    assert "--cov=agent_assure --cov-branch --cov-report=" in run_step["run"]
    assert run_step["run"].count("--cov-fail-under=0") == 1
    upload = next(
        step
        for step in shards["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    )
    assert upload["uses"].endswith("@ea165f8d65b6e75b540449e92b4886f43607fa02")
    assert upload["if"] == "${{ always() }}"
    assert upload["with"]["name"] == "coverage-${{ matrix.shard }}"
    assert upload["with"]["path"] == ".coverage.${{ matrix.shard }}"
    assert upload["with"]["include-hidden-files"] is True
    assert upload["with"]["if-no-files-found"] == "error"
    assert upload["with"]["retention-days"] == 1

    gate = jobs["coverage-gate"]
    assert gate["runs-on"] == "ubuntu-24.04"
    assert gate["timeout-minutes"] == 15
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
    assert "--cov-fail-under=0" not in gate_commands
    assert "--fail-under 68" in gate_commands
    expected_critical_floors = {
        "src/agent_assure/live/": 65,
        "src/agent_assure/privacy/": 78,
        "src/agent_assure/mutation/": 74,
        "src/agent_assure/study/": 78,
        "src/agent_assure/schema/": 67,
        "src/agent_assure/policies/": 85,
        "src/agent_assure/statistics/": 82,
        "src/agent_assure/cli/": 67,
    }
    assert gate_commands.count("--critical-prefix") == len(expected_critical_floors)
    for prefix, floor in expected_critical_floors.items():
        assert f"--critical-prefix {prefix}={floor}" in gate_commands

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["coverage"]["run"] == {
        "branch": True,
        "source": ["agent_assure"],
        "relative_files": True,
    }
    assert project["tool"]["coverage"]["report"]["fail_under"] == 80


def test_release_documentation_matches_the_ci_coverage_policy() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    shards = workflow["jobs"]["coverage-shards"]
    gate_commands = "\n".join(
        str(step.get("run", "")) for step in workflow["jobs"]["coverage-gate"]["steps"]
    )
    pure_branch_match = re.search(r"--report coverage\.json --fail-under ([0-9.]+)", gate_commands)
    assert pure_branch_match is not None
    critical_floors = dict(
        re.findall(
            r"--critical-prefix src/agent_assure/([A-Za-z0-9_-]+)/=([0-9.]+)",
            gate_commands,
        )
    )
    assert critical_floors
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    combined_floor = project["tool"]["coverage"]["report"]["fail_under"]
    documentation = " ".join(
        (ROOT / "docs" / "release_pypi.md").read_text(encoding="utf-8").split()
    )

    shard_count = len(shards["strategy"]["matrix"]["include"])
    shard_count_word = {
        1: "one",
        2: "two",
        3: "three",
        4: "four",
        5: "five",
        6: "six",
        7: "seven",
        8: "eight",
        9: "nine",
        10: "ten",
    }.get(shard_count, str(shard_count))
    assert f"requires all {shard_count_word} exact coverage shards" in documentation
    assert (
        f"enforces {combined_floor}% combined statement/branch coverage and a "
        f"{pure_branch_match.group(1)}% repository-wide pure branch floor" in documentation
    )
    coverage_section = documentation.split("The `coverage-gate` status", maxsplit=1)[1].split(
        "## Owner Setup", maxsplit=1
    )[0]
    documented_critical_floors = dict(
        re.findall(r"`([A-Za-z0-9_-]+)/` ([0-9.]+)%", coverage_section)
    )
    assert documented_critical_floors == critical_floors
    assert (
        "databases that are oversized, change during inspection, are corrupt or non-branch, "
        "contain separator-normalization path collisions, or have incomplete source "
        "inventories before combination" in documentation
    )
    assert "combines only their named files" in documentation
    assert f"finite {shards['timeout-minutes']}-minute ceiling" in documentation
