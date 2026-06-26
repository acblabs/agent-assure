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
    data = loaded.data
    defaults_data = dict(_mapping(data.get("defaults", {})))
    expectation_defaults = _mapping(
        defaults_data.pop("expectation", defaults_data.pop("expectation_defaults", {}))
    )
    defaults = SuiteDefaults(**defaults_data)
    cases: list[SuiteCase] = []
    expectations: list[Expectation] = []
    for case_data in _sequence(data.get("cases", ())):
        case_map = _mapping(case_data)
        expectation_data = _merge_expectation_defaults(
            expectation_defaults,
            _mapping(case_map.get("expectation", {})),
        )
        expectation_data.setdefault("case_id", str(case_map["case_id"]))
        expectation_data.setdefault("expectation_id", f"{case_map['case_id']}:expectation")
        expectation_without_digest = Expectation(**expectation_data)
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
            case_id=str(case_map["case_id"]),
            title=str(case_map["title"]),
            expectation_id=expectation.expectation_id,
            fixture_id=_optional_string(case_map.get("fixture_id")),
            tags=tuple(str(tag) for tag in _sequence(case_map.get("tags", ()))),
        )
        cases.append(case)
        expectations.append(expectation)
    return CompiledSuite(
        suite_id=str(data["suite_id"]),
        suite_version=str(data["suite_version"]),
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
    return str(value)


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
