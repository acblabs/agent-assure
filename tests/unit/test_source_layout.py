from __future__ import annotations

from pathlib import Path

import pytest

from agent_assure.source_layout import source_checkout_component


def test_source_checkout_component_resolves_verified_repository_path(tmp_path: Path) -> None:
    repository_root = tmp_path / "agent-assure"
    module_file = repository_root / "src" / "agent_assure" / "schema" / "validation.py"
    component = repository_root / "schemas" / "v0.5.0" / "run-set.schema.json"
    module_file.parent.mkdir(parents=True)
    component.parent.mkdir(parents=True)
    module_file.write_text("", encoding="utf-8")
    component.write_text("{}", encoding="utf-8")
    (repository_root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    resolved = source_checkout_component(
        module_file,
        "schemas/v0.5.0/run-set.schema.json",
    )

    assert resolved == component.resolve()


def test_source_checkout_component_ignores_adjacent_installed_schema(
    tmp_path: Path,
) -> None:
    environment = tmp_path / "venv"
    module_file = (
        environment / "Lib" / "site-packages" / "agent_assure" / "schema" / "validation.py"
    )
    adjacent_schema = environment / "Lib" / "schemas" / "v0.5.0" / "run-set.schema.json"
    module_file.parent.mkdir(parents=True)
    adjacent_schema.parent.mkdir(parents=True)
    module_file.write_text("", encoding="utf-8")
    adjacent_schema.write_text("{}", encoding="utf-8")

    resolved = source_checkout_component(
        module_file,
        "schemas/v0.5.0/run-set.schema.json",
    )

    assert resolved is None


def test_source_checkout_component_rejects_repository_escape(tmp_path: Path) -> None:
    repository_root = tmp_path / "agent-assure"
    module_file = repository_root / "src" / "agent_assure" / "mutation" / "catalog.py"
    module_file.parent.mkdir(parents=True)
    module_file.write_text("", encoding="utf-8")
    (repository_root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="escaped the repository root"):
        source_checkout_component(module_file, "../outside.json")
