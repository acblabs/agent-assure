from __future__ import annotations

import json

import pytest

from agent_assure.io_limits import MAX_JSON_DEPTH, load_json_bounded, loads_json_bounded


def test_load_json_bounded_accepts_maximum_nesting_depth(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    nested_array_count = MAX_JSON_DEPTH - 1
    path.write_text(
        '{"value":' + ("[" * nested_array_count) + "0" + ("]" * nested_array_count) + "}",
        encoding="utf-8",
    )

    payload = load_json_bounded(path)

    assert "value" in payload


def test_load_json_bounded_rejects_excessive_nesting(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    nested_array_count = MAX_JSON_DEPTH
    path.write_text(
        '{"value":' + ("[" * nested_array_count) + "0" + ("]" * nested_array_count) + "}",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
        load_json_bounded(path)


def test_load_json_bounded_ignores_delimiters_and_escapes_in_strings(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    expected = {
        "text": ("[{" * (MAX_JSON_DEPTH + 1)) + ' "quoted" \\ tail',
        "nested": {"valid": True},
    }
    path.write_text(json.dumps(expected), encoding="utf-8")

    assert load_json_bounded(path) == expected


def test_load_json_bounded_converts_decoder_recursion_error(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    path.write_text("{}", encoding="utf-8")

    def raise_recursion_error(_text: str, **_kwargs: object) -> object:
        raise RecursionError("decoder recursion limit")

    monkeypatch.setattr("agent_assure.io_limits.json.loads", raise_recursion_error)

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
        load_json_bounded(path)


def test_load_json_bounded_rejects_non_object_root(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="root must be an object"):
        load_json_bounded(path)


@pytest.mark.parametrize(
    "payload",
    (
        '{"decision":"allow","decision":"deny"}',
        '{"outer":{"decision":"allow","decision":"deny"}}',
    ),
)
def test_loads_json_bounded_rejects_duplicate_object_keys(payload: str) -> None:
    with pytest.raises(ValueError, match="contains duplicate object keys"):
        loads_json_bounded(payload, label="test JSON")


def test_loads_json_bounded_rejects_escaped_equivalent_duplicate_keys() -> None:
    with pytest.raises(ValueError, match="contains duplicate object keys"):
        loads_json_bounded('{"decision":1,"dec\\u0069sion":2}', label="test JSON")


def test_loads_json_bounded_allows_same_key_in_separate_objects() -> None:
    assert loads_json_bounded('[{"decision":1},{"decision":2}]', label="test JSON") == [
        {"decision": 1},
        {"decision": 2},
    ]


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_loads_json_bounded_rejects_non_finite_constants(constant: str) -> None:
    with pytest.raises(ValueError, match="contains a non-finite numeric value"):
        loads_json_bounded(f'{{"value":{constant}}}', label="test JSON")


def test_loads_json_bounded_rejects_float_overflow() -> None:
    with pytest.raises(ValueError, match="contains a non-finite numeric value"):
        loads_json_bounded('{"value":1e9999}', label="test JSON")
