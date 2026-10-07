from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.update_golden as update_golden


@pytest.mark.parametrize(
    ("validation_path", "expected_failure"),
    (
        ("frozen-jsonschema+semantic-replay", None),
        (
            "frozen-jsonschema",
            "legacy replay golden is invalid: legacy.json "
            "(unexpected validation path: frozen-jsonschema)",
        ),
    ),
)
def test_legacy_replay_golden_requires_semantic_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    validation_path: str,
    expected_failure: str | None,
) -> None:
    raw = b'{"schema_version":"0.5.0"}\n'
    path = tmp_path / "legacy.json"
    monkeypatch.setattr(update_golden, "ROOT", tmp_path)
    monkeypatch.setattr(
        update_golden,
        "read_file_bounded",
        lambda *_args, **_kwargs: SimpleNamespace(data=raw),
    )
    monkeypatch.setattr(
        update_golden,
        "load_json_bytes_bounded",
        lambda *_args, **_kwargs: {"schema_version": "0.5.0"},
    )
    monkeypatch.setattr(
        update_golden,
        "validate_artifact_payload",
        lambda *_args, **_kwargs: validation_path,
    )
    failures: list[str] = []

    update_golden._check_legacy_replay_golden(
        path,
        artifact_kind="compiled-suite",
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        failures=failures,
    )

    assert failures == ([] if expected_failure is None else [expected_failure])


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
