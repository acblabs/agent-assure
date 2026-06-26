from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class YamlWarning:
    path: str
    message: str
    line: int
    column: int


@dataclass(frozen=True)
class LoadedYaml:
    data: dict[str, Any]
    warnings: tuple[YamlWarning, ...]


AMBIGUOUS_TAGS = {
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:timestamp",
}


def load_yaml_nodes(path: Path) -> LoadedYaml:
    text = path.read_text(encoding="utf-8")
    node = yaml.compose(text)
    warnings: list[YamlWarning] = []
    data = _convert_node(node, "$", warnings)
    if not isinstance(data, dict):
        raise ValueError("suite YAML root must be a mapping")
    return LoadedYaml(data=data, warnings=tuple(warnings))


def _convert_node(node: yaml.Node | None, path: str, warnings: list[YamlWarning]) -> Any:
    if node is None:
        return {}
    if isinstance(node, yaml.MappingNode):
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = str(_convert_node(key_node, path, warnings))
            result[key] = _convert_node(value_node, f"{path}.{key}", warnings)
        return result
    if isinstance(node, yaml.SequenceNode):
        return tuple(_convert_node(item, f"{path}[]", warnings) for item in node.value)
    if isinstance(node, yaml.ScalarNode):
        if unicodedata.normalize("NFC", node.value) != node.value:
            warnings.append(
                YamlWarning(
                    path=path,
                    message="string is not NFC-normalized",
                    line=node.start_mark.line + 1,
                    column=node.start_mark.column + 1,
                )
            )
        if node.tag in AMBIGUOUS_TAGS:
            warnings.append(
                YamlWarning(
                    path=path,
                    message=f"ambiguous scalar preserved as string: {node.value!r}",
                    line=node.start_mark.line + 1,
                    column=node.start_mark.column + 1,
                )
            )
            return node.value
        if node.tag == "tag:yaml.org,2002:bool":
            return node.value.lower() in {"true", "yes", "on"}
        if node.tag == "tag:yaml.org,2002:null":
            return None
        return node.value
    raise TypeError(f"unsupported YAML node: {type(node).__name__}")
