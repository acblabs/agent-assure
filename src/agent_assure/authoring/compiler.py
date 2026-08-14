from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_assure.authoring.yaml_nodes import LoadedYaml, load_yaml_nodes
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults


def compile_suite(path: Path) -> CompiledSuite:
    loaded = load_yaml_nodes(path)
    return compile_loaded_suite(loaded, source_digest=sha256_hexdigest(loaded.data))


def compile_loaded_suite(loaded: LoadedYaml, source_digest: str) -> CompiledSuite:
    data = _mapping(loaded.data)
    _reject_unknown_keys(
        data,
        allowed=(
            "suite_id",
            "suite_version",
            "defaults",
            "cases",
        ),
        owner="suite",
    )
    defaults_data = dict(_mapping(data.get("defaults", {})))
    if "expectation" in defaults_data and "expectation_defaults" in defaults_data:
        raise ValueError("defaults must not declare both expectation and expectation_defaults")
    if "runner_id" not in defaults_data:
        raise ValueError("suite defaults require an explicit runner_id")
    expectation_defaults = _mapping(
        defaults_data.pop("expectation", defaults_data.pop("expectation_defaults", {}))
    )
    defaults = SuiteDefaults(**defaults_data)
    cases: list[SuiteCase] = []
    expectations: list[Expectation] = []
    for case_data in _sequence(data.get("cases", ())):
        case_map = _mapping(case_data)
        _reject_unknown_keys(
            case_map,
            allowed=(
                "case_id",
                "title",
                "fixture_id",
                "tags",
                "expectation",
            ),
            owner="suite case",
        )
        case_id = _required_string(case_map.get("case_id"), owner="case_id")
        expectation_override = _mapping(case_map.get("expectation", {}))
        expectation_data = _merge_expectation_defaults(
            expectation_defaults,
            expectation_override,
        )
        if "allowed_tools" in expectation_override:
            expectation_data["allowed_tools_override"] = True
        expectation_data.setdefault("case_id", case_id)
        expectation_data.setdefault("expectation_id", f"{case_id}:expectation")
        expectation_without_digest = Expectation(**expectation_data)
        _validate_provider_boundary(expectation_without_digest)
        expectation = expectation_without_digest.model_copy(
            update={
                "expectation_digest": sha256_hexdigest(
                    expectation_without_digest.model_dump(
                        mode="json",
                        exclude={"expectation_digest"},
                    )
                )
            }
        )
        case = SuiteCase(
            case_id=case_id,
            title=_required_string(case_map.get("title"), owner="title"),
            expectation_id=expectation.expectation_id,
            fixture_id=_optional_string(case_map.get("fixture_id")),
            tags=_string_sequence(case_map.get("tags", ()), owner="tags"),
        )
        cases.append(case)
        expectations.append(expectation)
    return CompiledSuite(
        suite_id=_required_string(data.get("suite_id"), owner="suite_id"),
        suite_version=_required_string(data.get("suite_version"), owner="suite_version"),
        defaults=defaults,
        cases=tuple(cases),
        resolved_expectations=tuple(expectations),
        source_digest=source_digest,
    )


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("expected mapping")
    return value


def _sequence(value: Any) -> tuple[Any, ...]:
    if not isinstance(value, tuple | list):
        raise TypeError("expected sequence")
    return tuple(value)


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return _required_string(value, owner="fixture_id")


def _required_string(value: Any, *, owner: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{owner} must be a string")
    if not value:
        raise ValueError(f"{owner} must not be empty")
    return value


def _string_sequence(value: Any, *, owner: str) -> tuple[str, ...]:
    values = _sequence(value)
    return tuple(
        _required_string(item, owner=f"{owner}[{index}]") for index, item in enumerate(values)
    )


def _reject_unknown_keys(
    value: dict[str, Any],
    *,
    allowed: tuple[str, ...],
    owner: str,
) -> None:
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise ValueError(f"{owner} contains unknown keys: {', '.join(unknown)}")


def _validate_provider_boundary(expectation: Expectation) -> None:
    has_provider_constraint = bool(expectation.allowed_providers or expectation.forbidden_providers)
    has_review_or_outcome_boundary = bool(
        expectation.required_human_review or expectation.forbidden_outcomes
    )
    if has_provider_constraint and not has_review_or_outcome_boundary:
        raise ValueError(
            "provider allow/deny lists require required_human_review or "
            "at least one forbidden_outcome"
        )


def _merge_expectation_defaults(
    defaults: dict[str, Any],
    overrides: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(defaults)
    for key, value in overrides.items():
        if isinstance(merged.get(key), dict) and isinstance(value, dict):
            merged[key] = _merge_expectation_defaults(merged[key], value)
            continue
        merged[key] = value
    return merged
