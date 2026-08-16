from __future__ import annotations

import pytest

from agent_assure.schema.base import validate_rfc8785_safe_integers


def test_safe_integer_validation_allows_repeated_acyclic_aliases() -> None:
    shared = {"safe": (1 << 53) - 1}

    validate_rfc8785_safe_integers(
        {"first": shared, "second": shared},
        owner="aliased fixture",
    )


def test_safe_integer_validation_rejects_recursive_mapping() -> None:
    recursive: dict[str, object] = {}
    recursive["self"] = recursive

    with pytest.raises(ValueError, match=r"\$\.self.*cyclic reference"):
        validate_rfc8785_safe_integers(recursive, owner="recursive fixture")


def test_safe_integer_validation_rejects_recursive_sequence() -> None:
    recursive: list[object] = []
    recursive.append(recursive)

    with pytest.raises(ValueError, match=r"\$\[0\].*cyclic reference"):
        validate_rfc8785_safe_integers(recursive, owner="recursive fixture")
