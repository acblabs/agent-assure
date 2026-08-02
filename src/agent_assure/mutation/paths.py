from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy

from agent_assure.mutation.operators import PayloadChange


def structural_changed_paths(source: object, candidate: object) -> tuple[str, ...]:
    """Return deterministic RFC 6901 pointers for exact JSON structural changes.

    Container shape changes collapse to their parent pointer. Otherwise the
    comparison recurses through mappings and equal-length lists. Scalar equality
    is type-sensitive so JSON booleans and integers cannot compare equal by
    Python coercion.
    """
    changed: list[str] = []
    _collect_structural_changed_paths(source, candidate, pointer="", changed=changed)
    return tuple(sorted(changed))


def apply_payload_changes(
    source: Mapping[str, object],
    changes: tuple[PayloadChange, ...],
) -> dict[str, object]:
    """Apply exact pointer replacements to a deep copy of a JSON object."""
    paths = tuple(change.path for change in changes)
    if len(set(paths)) != len(paths):
        raise ValueError("mutation changes must use unique JSON Pointer paths")
    candidate = deepcopy(dict(source))
    for change in changes:
        _replace_pointer(candidate, change.path, deepcopy(change.value))
    return candidate


def paths_are_permitted(
    changed_paths: tuple[str, ...],
    permitted_templates: tuple[str, ...],
) -> bool:
    return all(
        any(pointer_matches_template(path, template) for template in permitted_templates)
        for path in changed_paths
    )


def pointer_matches_template(pointer: str, template: str) -> bool:
    parts = parse_json_pointer(pointer)
    template_parts = parse_json_pointer(template, allow_wildcard=True)
    return len(parts) == len(template_parts) and all(
        expected == "*" or actual == expected
        for actual, expected in zip(parts, template_parts, strict=True)
    )


def parse_json_pointer(pointer: str, *, allow_wildcard: bool = False) -> tuple[str, ...]:
    if not pointer.startswith("/"):
        raise ValueError("JSON Pointer must start with '/'")
    encoded_parts = pointer[1:].split("/")
    parts = tuple(_decode_pointer_part(part) for part in encoded_parts)
    if not allow_wildcard and "*" in parts:
        raise ValueError("exact JSON Pointer cannot contain a wildcard")
    return parts


def _replace_pointer(root: dict[str, object], pointer: str, value: object) -> None:
    parts = parse_json_pointer(pointer)
    if not parts:
        raise ValueError("document-root mutation is forbidden")
    current: object = root
    for part in parts[:-1]:
        if isinstance(current, Mapping):
            if part not in current:
                raise ValueError(f"mutation path does not exist: {pointer}")
            current = current[part]
            continue
        if isinstance(current, Sequence) and not isinstance(current, str | bytes | bytearray):
            index = _array_index(part, pointer)
            try:
                current = current[index]
            except IndexError as exc:
                raise ValueError(f"mutation array index is out of range: {pointer}") from exc
            continue
        raise ValueError(f"mutation path crosses a scalar value: {pointer}")
    final = parts[-1]
    if isinstance(current, dict):
        current[final] = value
        return
    if isinstance(current, list):
        index = _array_index(final, pointer)
        try:
            current[index] = value
        except IndexError as exc:
            raise ValueError(f"mutation array index is out of range: {pointer}") from exc
        return
    raise ValueError(f"mutation path parent is not a container: {pointer}")


def _array_index(part: str, pointer: str) -> int:
    if not part.isdigit() or (len(part) > 1 and part.startswith("0")):
        raise ValueError(f"mutation path has an invalid array index: {pointer}")
    return int(part)


def _decode_pointer_part(part: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(part):
        character = part[index]
        if character != "~":
            decoded.append(character)
            index += 1
            continue
        if index + 1 >= len(part) or part[index + 1] not in {"0", "1"}:
            raise ValueError("JSON Pointer contains an invalid escape")
        decoded.append("~" if part[index + 1] == "0" else "/")
        index += 2
    return "".join(decoded)


def _collect_structural_changed_paths(
    source: object,
    candidate: object,
    *,
    pointer: str,
    changed: list[str],
) -> None:
    if type(source) is not type(candidate):
        changed.append(pointer)
        return
    if isinstance(source, dict) and isinstance(candidate, dict):
        if set(source) != set(candidate):
            changed.append(pointer)
            return
        for key in sorted(source):
            child = f"{pointer}/{_encode_pointer_part(key)}"
            _collect_structural_changed_paths(
                source[key],
                candidate[key],
                pointer=child,
                changed=changed,
            )
        return
    if isinstance(source, list) and isinstance(candidate, list):
        if len(source) != len(candidate):
            changed.append(pointer)
            return
        for index, (source_item, candidate_item) in enumerate(
            zip(source, candidate, strict=True)
        ):
            _collect_structural_changed_paths(
                source_item,
                candidate_item,
                pointer=f"{pointer}/{index}",
                changed=changed,
            )
        return
    if source != candidate:
        changed.append(pointer)


def _encode_pointer_part(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")
