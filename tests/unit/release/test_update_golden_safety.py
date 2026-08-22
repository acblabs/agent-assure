from __future__ import annotations

from pathlib import Path

import pytest

import scripts.update_golden as update_golden


def test_update_golden_uses_safe_atomic_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_golden, "ROOT", tmp_path)
    destination = tmp_path / "goldens" / "artifact.json"
    failures: list[str] = []

    update_golden._check_or_update_golden(
        destination,
        "generated\n",
        update=True,
        failures=failures,
    )

    assert failures == []
    assert destination.read_text(encoding="utf-8") == "generated\n"


def test_update_golden_refuses_linked_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_golden, "ROOT", tmp_path)
    target = tmp_path / "outside.txt"
    target.write_text("preserve\n", encoding="utf-8")
    destination = tmp_path / "goldens" / "artifact.json"
    destination.parent.mkdir()
    try:
        destination.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    failures: list[str] = []

    update_golden._check_or_update_golden(
        destination,
        "replacement\n",
        update=True,
        failures=failures,
    )

    assert len(failures) == 1
    assert failures[0].startswith("unsafe golden destination:")
    assert "artifact.json" in failures[0]
    assert target.read_text(encoding="utf-8") == "preserve\n"
    assert destination.is_symlink()


def test_check_golden_refuses_linked_source_even_when_content_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_golden, "ROOT", tmp_path)
    target = tmp_path / "outside.txt"
    target.write_text("generated\n", encoding="utf-8")
    destination = tmp_path / "goldens" / "artifact.json"
    destination.parent.mkdir()
    try:
        destination.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    failures: list[str] = []

    update_golden._check_or_update_golden(
        destination,
        "generated\n",
        update=False,
        failures=failures,
    )

    assert len(failures) == 1
    assert failures[0].startswith("unsafe golden file:")
