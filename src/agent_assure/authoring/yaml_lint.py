from __future__ import annotations

from pathlib import Path

from agent_assure.authoring.yaml_nodes import YamlWarning, load_yaml_nodes


def lint_yaml(path: Path) -> tuple[YamlWarning, ...]:
    return load_yaml_nodes(path).warnings
