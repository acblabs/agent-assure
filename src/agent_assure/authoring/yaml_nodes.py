from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_assure.io_limits import read_text_bounded
from agent_assure.privacy.redaction import redact_text

MAX_YAML_BYTES = 1_048_576
MAX_YAML_NODE_COUNT = 100_000
MAX_YAML_DEPTH = 80
MAX_YAML_DIAGNOSTIC_CHARS = 512


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


@dataclass
class _YamlConversionState:
    label: str = "suite YAML"
    seen_node_ids: set[int] = field(default_factory=set)
    node_count: int = 0


AMBIGUOUS_TAGS = {
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:timestamp",
}


def load_yaml_nodes(path: Path, *, label: str = "suite YAML") -> LoadedYaml:
    text = read_text_bounded(path, max_bytes=MAX_YAML_BYTES, label=label)
    return load_yaml_nodes_text(text, label=label)


def load_yaml_nodes_text(text: str, *, label: str = "suite YAML") -> LoadedYaml:
    node = _compose_yaml(text, label=label)
    warnings: list[YamlWarning] = []
    data = _convert_node(
        node,
        "$",
        warnings,
        state=_YamlConversionState(label=label),
        depth=0,
    )
    if not isinstance(data, dict):
        raise ValueError(f"{label} root must be a mapping")
    return LoadedYaml(data=data, warnings=tuple(warnings))


def validate_yaml_nodes_text(text: str, *, label: str = "suite YAML") -> None:
    node = _compose_yaml(text, label=label)
    _convert_node(
        node,
        "$",
        [],
        state=_YamlConversionState(label=label),
        depth=0,
    )


def safe_load_yaml_text(text: str, *, label: str) -> Any:
    validate_yaml_nodes_text(text, label=label)
    try:
        return yaml.safe_load(text)
    except RecursionError as exc:
        raise ValueError(f"{label} exceeds maximum supported nesting depth") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"{label} is invalid YAML") from exc


def _compose_yaml(text: str, *, label: str) -> yaml.Node | None:
    try:
        return yaml.compose(text, Loader=yaml.SafeLoader)
    except RecursionError as exc:
        raise ValueError(f"{label} exceeds maximum supported nesting depth") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"{label} is invalid YAML") from exc


def _convert_node(
    node: yaml.Node | None,
    path: str,
    warnings: list[YamlWarning],
    *,
    state: _YamlConversionState,
    depth: int,
) -> Any:
    if node is None:
        return {}
    _record_node_visit(node, path, state=state, depth=depth)
    if isinstance(node, yaml.MappingNode):
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ValueError(
                    f"{state.label} merge keys are not supported at "
                    f"{_safe_yaml_path(path)}: "
                    f"line {key_node.start_mark.line + 1}, "
                    f"column {key_node.start_mark.column + 1}"
                )
            if key_node.tag != "tag:yaml.org,2002:str":
                raise ValueError(
                    f"{state.label} mapping keys must be strings at "
                    f"{_safe_yaml_path(path)}: "
                    f"line {key_node.start_mark.line + 1}, "
                    f"column {key_node.start_mark.column + 1}"
                )
            key = str(
                _convert_node(
                    key_node,
                    path,
                    warnings,
                    state=state,
                    depth=depth + 1,
                )
            )
            if key in result:
                raise ValueError(
                    f"duplicate YAML mapping key at "
                    f"{_safe_yaml_path(f'{path}.{key}')}: "
                    f"line {key_node.start_mark.line + 1}, "
                    f"column {key_node.start_mark.column + 1}"
                )
            result[key] = _convert_node(
                value_node,
                f"{path}.{key}",
                warnings,
                state=state,
                depth=depth + 1,
            )
        return result
    if isinstance(node, yaml.SequenceNode):
        return tuple(
            _convert_node(
                item,
                f"{path}[]",
                warnings,
                state=state,
                depth=depth + 1,
            )
            for item in node.value
        )
    if isinstance(node, yaml.ScalarNode):
        if unicodedata.normalize("NFC", node.value) != node.value:
            warnings.append(
                YamlWarning(
                    path=_safe_yaml_path(path),
                    message="string is not NFC-normalized",
                    line=node.start_mark.line + 1,
                    column=node.start_mark.column + 1,
                )
            )
        if node.tag in AMBIGUOUS_TAGS:
            warnings.append(
                YamlWarning(
                    path=_safe_yaml_path(path),
                    message=(
                        f"ambiguous scalar preserved as string: {_safe_yaml_diagnostic(node.value)}"
                    ),
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


def _record_node_visit(
    node: yaml.Node,
    path: str,
    *,
    state: _YamlConversionState,
    depth: int,
) -> None:
    if depth > MAX_YAML_DEPTH:
        raise ValueError(f"{state.label} exceeds maximum supported nesting depth")
    node_id = id(node)
    if node_id in state.seen_node_ids:
        raise ValueError(
            f"{state.label} aliases are not supported because alias expansion can "
            f"exhaust resources at {_safe_yaml_path(path)}"
        )
    state.seen_node_ids.add(node_id)
    state.node_count += 1
    if state.node_count > MAX_YAML_NODE_COUNT:
        raise ValueError(f"{state.label} exceeds maximum supported node count")


def _safe_yaml_path(path: str) -> str:
    compact = " ".join(path.split())
    redacted = redact_text(compact)
    escaped = "".join(
        character if character.isprintable() else character.encode("unicode_escape").decode("ascii")
        for character in redacted
    )
    return escaped[:MAX_YAML_DIAGNOSTIC_CHARS]


def _safe_yaml_diagnostic(value: str) -> str:
    compact = " ".join(value.split())
    escaped = ascii(redact_text(compact))
    return escaped[:MAX_YAML_DIAGNOSTIC_CHARS]
