from __future__ import annotations


def required_string(data: dict[str, object], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def optional_string(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise TypeError("expected string sequence")
    return tuple(str(item) for item in value)
