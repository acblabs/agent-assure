from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Protocol, cast

import pytest

from agent_assure.rooted_io import BoundedFileDescriptor

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import check_packaged_examples as checker  # type: ignore[import-not-found]  # noqa: E402
from check_packaged_examples import (  # noqa: E402
    compare_packaged_examples,
)


class _BoundedOpen(Protocol):
    def __call__(
        self,
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
    ) -> BoundedFileDescriptor: ...


def test_packaged_examples_match_when_mirrored_resources_match(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")

    drift = compare_packaged_examples(top_level, packaged)

    assert drift == []


def test_packaged_examples_report_content_drift(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="top-level")
    (
        packaged / "prior_auth_synthetic" / "fixtures" / "shared" / "requests" / "case.json"
    ).write_text("packaged\n", encoding="utf-8")

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].example == "prior_auth_synthetic"
    assert drift[0].relative_path.as_posix() == "fixtures/shared/requests/case.json"
    assert "differ" in drift[0].message


def test_packaged_examples_report_missing_resource(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    (packaged / "expense_approval_minimal" / "variants" / "baseline.yaml").unlink()

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].example == "expense_approval_minimal"
    assert drift[0].relative_path.as_posix() == "variants/baseline.yaml"
    assert "missing from packaged resources" in drift[0].message


def test_packaged_examples_report_evidence_sensitivity_contract_drift(
    tmp_path: Path,
) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    (packaged / "evidence_sensitivity" / "knowledge-contract.yaml").write_text(
        "authority_level: advisory\n",
        encoding="utf-8",
    )

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].example == "evidence_sensitivity"
    assert drift[0].relative_path.as_posix() == "knowledge-contract.yaml"
    assert "differ" in drift[0].message


def test_packaged_examples_report_evidence_reversed_suite_drift(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    (packaged / "evidence_sensitivity" / "evidence_reversed_suite.yaml").write_text(
        "suite_id: retargeted-reversed-control\n",
        encoding="utf-8",
    )

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].example == "evidence_sensitivity"
    assert drift[0].relative_path.as_posix() == "evidence_reversed_suite.yaml"
    assert "differ" in drift[0].message


def test_packaged_examples_report_evidence_reversed_fixture_drift(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    reversed_model_output = (
        packaged
        / "evidence_sensitivity"
        / "fixtures"
        / "evidence_reversed"
        / "model_outputs"
        / "synthetic-benefit-eligibility.json"
    )
    reversed_model_output.write_text("retargeted\n", encoding="utf-8")

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].example == "evidence_sensitivity"
    assert drift[0].relative_path.as_posix() == (
        "fixtures/evidence_reversed/model_outputs/synthetic-benefit-eligibility.json"
    )
    assert "differ" in drift[0].message


def test_packaged_examples_report_reproduction_index_drift(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    (packaged / "process_equivalence_reproduction_index.json").write_text(
        "stale\n",
        encoding="utf-8",
    )

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].example == "<root>"
    assert drift[0].relative_path.as_posix() == "process_equivalence_reproduction_index.json"


def test_packaged_examples_reject_unexpected_packaged_root_file(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    (packaged / "evidence_sensitivity" / "unexpected.py").write_text(
        "raise RuntimeError\n",
        encoding="utf-8",
    )

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].relative_path == Path("unexpected.py")
    assert "unexpected packaged root entry" in drift[0].message


def test_packaged_examples_reject_equal_content_symlink(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    target = top_level / "evidence_sensitivity" / "knowledge-contract.yaml"
    linked = packaged / "evidence_sensitivity" / "knowledge-contract.yaml"
    linked.unlink()
    try:
        linked.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    drift = compare_packaged_examples(top_level, packaged)

    assert any("symbolic link or reparse point" in item.message for item in drift)


def test_packaged_examples_bound_mirrored_directory_depth(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    for root in (top_level, packaged):
        nested = root / "evidence_sensitivity" / "fixtures"
        for index in range(34):
            nested /= f"level-{index}"
        nested.mkdir(parents=True)
        (nested / "case.json").write_text("same\n", encoding="utf-8")

    drift = compare_packaged_examples(top_level, packaged)

    assert any("exceeds mirrored depth" in item.message for item in drift)


def test_packaged_examples_enforce_file_limit_at_rooted_read_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    target_root = packaged / "evidence_sensitivity"
    target = target_root / "knowledge-contract.yaml"
    original_bytes = target.read_bytes()
    original_open = cast(_BoundedOpen, checker.open_file_bounded_at)
    injected = False
    maximum = 64

    def grow_before_read(
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
    ) -> BoundedFileDescriptor:
        nonlocal injected
        if (
            not injected
            and root == target_root
            and Path(relative_path) == Path("knowledge-contract.yaml")
        ):
            injected = True
            target.write_bytes(b"x" * (maximum + 1))
            try:
                return original_open(
                    root,
                    relative_path,
                    max_bytes=max_bytes,
                    label=label,
                )
            finally:
                target.write_bytes(original_bytes)
        return original_open(
            root,
            relative_path,
            max_bytes=max_bytes,
            label=label,
        )

    monkeypatch.setattr(checker, "MAX_MIRRORED_FILE_BYTES", maximum)
    monkeypatch.setattr(checker, "open_file_bounded_at", grow_before_read)

    drift = compare_packaged_examples(top_level, packaged)

    assert injected
    finding = next(
        item
        for item in drift
        if item.example == "evidence_sensitivity"
        and item.relative_path == Path("knowledge-contract.yaml")
    )
    assert "maximum supported size" in finding.message
    assert not any(
        item.relative_path == finding.relative_path and "counterpart" in item.message
        for item in drift
    )


def test_packaged_examples_reject_file_change_between_inventory_and_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    target_root = packaged / "evidence_sensitivity"
    target = target_root / "knowledge-contract.yaml"
    original_open = cast(_BoundedOpen, checker.open_file_bounded_at)
    injected = False

    def replace_before_read(
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
    ) -> BoundedFileDescriptor:
        nonlocal injected
        if (
            not injected
            and root == target_root
            and Path(relative_path) == Path("knowledge-contract.yaml")
        ):
            injected = True
            previous = target.stat()
            replacement = b"x" * previous.st_size
            target.write_bytes(replacement)
            os.utime(
                target,
                ns=(previous.st_atime_ns, previous.st_mtime_ns + 1_000_000_000),
            )
        return original_open(
            root,
            relative_path,
            max_bytes=max_bytes,
            label=label,
        )

    monkeypatch.setattr(checker, "open_file_bounded_at", replace_before_read)

    drift = compare_packaged_examples(top_level, packaged)

    assert injected
    matching = [
        item
        for item in drift
        if item.example == "evidence_sensitivity"
        and item.relative_path == Path("knowledge-contract.yaml")
    ]
    assert len(matching) == 1
    assert "changed between inventory and bounded read" in matching[0].message


def _write_example_pair(tmp_path: Path, *, content: str) -> tuple[Path, Path]:
    top_level = tmp_path / "examples"
    packaged = tmp_path / "src" / "agent_assure" / "examples"
    for root in (top_level, packaged):
        root.mkdir(parents=True, exist_ok=True)
        (root / "process_equivalence_reproduction_index.json").write_text(
            f"{content}\n",
            encoding="utf-8",
        )
        for example in (
            "prior_auth_synthetic",
            "expense_approval_minimal",
            "langgraph_expense_assurance",
            "adk_process_assurance",
            "process_measurement_cases",
            "streaming_process_regression",
            "evidence_sensitivity",
        ):
            example_root = root / example
            (example_root / "fixtures" / "shared" / "requests").mkdir(parents=True)
            (example_root / "events").mkdir(parents=True)
            (example_root / "variants").mkdir(parents=True)
            (example_root / "README.md").write_text("# Example\n", encoding="utf-8")
            (example_root / "suite.yaml").write_text(
                f"suite_id: {example}\n",
                encoding="utf-8",
            )
            (example_root / "variants" / "baseline.yaml").write_text(
                "variant_id: baseline\n",
                encoding="utf-8",
            )
            (example_root / "fixtures" / "shared" / "requests" / "case.json").write_text(
                f"{content}\n",
                encoding="utf-8",
            )
            (example_root / "events" / "baseline.jsonl").write_text(
                f"{content}\n",
                encoding="utf-8",
            )
            (example_root / "responsive_suite.yaml").write_text(
                "suite_id: responsive\n",
                encoding="utf-8",
            )
            (example_root / "evidence_inertial_suite.yaml").write_text(
                "suite_id: evidence-inertial\n",
                encoding="utf-8",
            )
            (example_root / "evidence_reversed_suite.yaml").write_text(
                "suite_id: evidence-reversed\n",
                encoding="utf-8",
            )
            (example_root / "knowledge-contract.yaml").write_text(
                "authority_level: authoritative\n",
                encoding="utf-8",
            )
            for fixture_kind in ("requests", "model_outputs", "tool_outputs"):
                fixture = (
                    example_root
                    / "fixtures"
                    / "evidence_reversed"
                    / fixture_kind
                    / "synthetic-benefit-eligibility.json"
                )
                fixture.parent.mkdir(parents=True)
                fixture.write_text(f"{content}\n", encoding="utf-8")
            (example_root / "corpora" / "policy_a").mkdir(parents=True)
            (example_root / "corpora" / "policy_a" / "corpus-manifest.json").write_text(
                f"{content}\n",
                encoding="utf-8",
            )
    return top_level, packaged
