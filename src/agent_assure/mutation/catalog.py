from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import cast

from agent_assure.mutation import operators
from agent_assure.mutation.operators import MutationTarget
from agent_assure.schema.common import ReasonCode
from agent_assure.schema.mutation import (
    AssuranceMutationOperator,
    AuthorshipRelationship,
    ExpectedDetectionContract,
    FindingSelector,
    IndependenceClass,
    OperatorAuthorship,
    OperatorImplementationComponent,
    OperatorOrigin,
    OperatorOriginKind,
    OperatorPrecondition,
    OperatorProvenance,
    RequiredFindingAlternatives,
    TargetControlProvenance,
    mutation_implementation_digest,
)
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite

TargetResolver = Callable[
    [CompiledSuite, RunSet, Mapping[str, object]],
    tuple[MutationTarget, ...],
]

_CONTROL_FIRST_SEEN_COMMITS = {
    "material_claims_have_evidence": "git:441fc73793fd9154a2830613dfe2a521ca3eeaa1",
    "human_review_required": "git:441fc73793fd9154a2830613dfe2a521ca3eeaa1",
    "tool_allowlist": "git:441fc73793fd9154a2830613dfe2a521ca3eeaa1",
}
_TARGET_CONTROL_COMPONENT_PATHS = {
    "material_claims_have_evidence": "agent_assure/policies/evidence.py",
    "human_review_required": "agent_assure/policies/human_review.py",
    "tool_allowlist": "agent_assure/policies/tools.py",
}
# Authored snapshots of the target controls when each operator was created. These
# values are deliberately not derived from the live implementation manifest. Once
# ``introduced_at_commit`` is stamped, the release provenance guard verifies each
# snapshot against the LF-normalized target-control blob in that commit.
_TARGET_CONTROL_CREATION_DIGESTS = {
    (
        "drop-material-evidence-link",
        "material_claims_have_evidence",
    ): "ab793747a5f3744c42c95cb43f12d67880988e2696cbc57f12d4f703311d7e99",
    (
        "bypass-required-human-review",
        "human_review_required",
    ): "5bf534408536881aacc96be591ae67ca22121a2de3626a632c899b32e2e15d9e",
    (
        "inject-forbidden-tool",
        "tool_allowlist",
    ): "36a3f9b02bf2262d2847e69ebe8e5c518a6c315359dd13c9382afcc9c4004e5e",
}
_IMPLEMENTATION_COMPONENT_PATHS = (
    ("agent_assure.version", "agent_assure/__init__.py"),
    ("canonical.digests", "agent_assure/canonical/digests.py"),
    ("canonical.jcs", "agent_assure/canonical/jcs.py"),
    ("canonical.normalize", "agent_assure/canonical/normalize.py"),
    ("evaluation.evaluator", "agent_assure/evaluation/evaluator.py"),
    ("evaluation.expectations", "agent_assure/evaluation/expectations.py"),
    ("evaluation.invariants", "agent_assure/evaluation/invariants.py"),
    ("fixtures.loader", "agent_assure/fixtures/loader.py"),
    ("io_limits", "agent_assure/io_limits.py"),
    ("mutation.catalog", "agent_assure/mutation/catalog.py"),
    ("mutation.detection", "agent_assure/mutation/detection.py"),
    ("mutation.execution", "agent_assure/mutation/execution.py"),
    (
        "mutation.introduction-snapshots",
        "agent_assure/mutation/introduction_snapshots.json",
    ),
    ("mutation.operators", "agent_assure/mutation/operators.py"),
    ("mutation.paths", "agent_assure/mutation/paths.py"),
    ("mutation.selection", "agent_assure/mutation/selection.py"),
    ("policies.base", "agent_assure/policies/base.py"),
    ("policies.catalog", "agent_assure/policies/catalog.py"),
    ("policies.evidence", "agent_assure/policies/evidence.py"),
    ("policies.human_review", "agent_assure/policies/human_review.py"),
    ("policies.injection", "agent_assure/policies/injection.py"),
    ("policies.output_schema", "agent_assure/policies/output_schema.py"),
    ("policies.privacy", "agent_assure/policies/privacy.py"),
    ("policies.providers", "agent_assure/policies/providers.py"),
    ("policies.review_boundary", "agent_assure/policies/review_boundary.py"),
    ("policies.runtime", "agent_assure/policies/runtime.py"),
    ("policies.tools", "agent_assure/policies/tools.py"),
    ("privacy.detectors", "agent_assure/privacy/detectors.py"),
    ("privacy.redaction", "agent_assure/privacy/redaction.py"),
    ("schema.base", "agent_assure/schema/base.py"),
    ("schema.common", "agent_assure/schema/common.py"),
    ("schema.environment", "agent_assure/schema/environment.py"),
    ("schema.evaluation", "agent_assure/schema/evaluation.py"),
    ("schema.expectation", "agent_assure/schema/expectation.py"),
    ("schema.export", "agent_assure/schema/export.py"),
    ("schema.mutation", "agent_assure/schema/mutation.py"),
    ("schema.privacy", "agent_assure/schema/privacy.py"),
    ("schema.provenance", "agent_assure/schema/provenance.py"),
    ("schema.run", "agent_assure/schema/run.py"),
    ("schema.runtime", "agent_assure/schema/runtime.py"),
    ("schema.suite", "agent_assure/schema/suite.py"),
    ("schema.usage", "agent_assure/schema/usage.py"),
    ("schema.validation", "agent_assure/schema/validation.py"),
    ("runner.ids", "agent_assure/runner/ids.py"),
    ("telemetry.context", "agent_assure/telemetry/context.py"),
    ("usage.aggregation", "agent_assure/usage/aggregation.py"),
)

_FROZEN_RUNSET_SCHEMA_PATHS = tuple(
    f"schemas/v{version}/run-set.schema.json"
    for version in ("0.1.0", "0.2.0", "0.3.1", "0.4.3", "0.5.0")
)

_CATALOG_COMPONENT_PATH = "agent_assure/mutation/catalog.py"
_INTRODUCTION_SNAPSHOT_PATH = "agent_assure/mutation/introduction_snapshots.json"
_INTRODUCTION_STAMP_PATTERN = re.compile(
    rb'introduced_at_commit="git:(?:uncommitted|[a-f0-9]{40})"'
)
_NORMALIZED_INTRODUCTION_STAMP = b'introduced_at_commit="git:uncommitted"'


@dataclass(frozen=True)
class RegisteredOperator:
    descriptor: AssuranceMutationOperator
    resolve_targets: TargetResolver
    limitations: tuple[str, ...]


class CatalogIntegrityError(RuntimeError):
    """The built-in catalog cannot establish its packaged implementation identity."""


def registered_operators() -> tuple[RegisteredOperator, ...]:
    """Return the lazily constructed, process-cached built-in operator catalog."""
    return _operator_catalog()


def built_in_evaluator_implementation_components(
) -> tuple[OperatorImplementationComponent, ...]:
    """Return the fail-closed first-party code/data closure for built-in evaluation.

    Python executes package initializers before imported submodules, and those
    initializers can import further modules. Binding the complete packaged Python
    tree avoids an identity gap when that import closure evolves. The legacy
    RunSet schemas are included because validation loads their bytes at runtime.
    """
    return _implementation_components()


def resolve_operator(operator_id: str) -> RegisteredOperator | None:
    """Resolve an operator, failing closed if catalog integrity cannot be established."""
    return next(
        (item for item in _operator_catalog() if item.descriptor.operator_id == operator_id),
        None,
    )


def target_control_component_path(control_id: str) -> str:
    """Return the packaged source path whose creation-time digest binds a control."""
    try:
        return _TARGET_CONTROL_COMPONENT_PATHS[control_id]
    except KeyError as exc:
        raise CatalogIntegrityError(
            f"target control has no provenance source mapping: {control_id}"
        ) from exc


def _registered_operator(
    *,
    operator_id: str,
    target_control_id: str,
    reason_code: ReasonCode,
    permitted_changed_paths: tuple[str, ...],
    preconditions: tuple[OperatorPrecondition, ...],
    resolver: TargetResolver,
    limitations: tuple[str, ...],
    implementation_components: tuple[OperatorImplementationComponent, ...],
) -> RegisteredOperator:
    operator_version = "1.0.0"
    implementation_digest = mutation_implementation_digest(
        operator_id=operator_id,
        operator_version=operator_version,
        components=implementation_components,
    )
    detector = ExpectedDetectionContract.build(
        operator_id=operator_id,
        target_control_ids=(target_control_id,),
        required_findings=RequiredFindingAlternatives(
            any_of=(
                FindingSelector(
                    control_id=target_control_id,
                    reason_code=reason_code,
                ),
            )
        ),
        prohibited_substitutes=(
            FindingSelector(
                control_id="runtime_success_required",
                reason_code=ReasonCode.RUNTIME_FAILED,
            ),
        ),
        expected_gate_effect="block",
        secondary_findings_allowed=True,
    )
    provenance = OperatorProvenance(
        operator_id=operator_id,
        operator_version=operator_version,
        implementation_digest=implementation_digest,
        implementation_components=implementation_components,
        introduction_components=_introduction_components(operator_id),
        introduced_at_commit="git:uncommitted",
        introduced_in_release="0.6.0",
        origin=OperatorOrigin(
            kind=OperatorOriginKind.first_party,
            references=("docs/evidence_carrying_releases.md",),
        ),
        target_controls=(
            TargetControlProvenance(
                control_id=target_control_id,
                first_seen_commit=_CONTROL_FIRST_SEEN_COMMITS[target_control_id],
                digest_at_operator_creation=_target_control_creation_digest(
                    operator_id,
                    target_control_id,
                ),
            ),
        ),
        authorship=OperatorAuthorship(
            relationship_to_control_author=AuthorshipRelationship.unknown,
        ),
    )
    descriptor = AssuranceMutationOperator.build(
        operator_id=operator_id,
        operator_version=operator_version,
        compatible_schema_versions=("0.5.0", "0.6.0"),
        preconditions=preconditions,
        permitted_changed_paths=tuple(sorted(permitted_changed_paths)),
        privacy_classification="synthetic_fixture_metadata",
        provenance=provenance,
        independence_class=IndependenceClass.first_party_postcontrol,
        implementation_digest=implementation_digest,
        expected_detection_contract=detector,
    )
    return RegisteredOperator(
        descriptor=descriptor,
        resolve_targets=resolver,
        limitations=limitations,
    )


def _implementation_components() -> tuple[OperatorImplementationComponent, ...]:
    components = []
    explicit_ids = {
        relative_path: component_id
        for component_id, relative_path in _IMPLEMENTATION_COMPONENT_PATHS
    }
    relative_paths = set(explicit_ids)
    relative_paths.update(_packaged_python_component_paths())
    relative_paths.update(_FROZEN_RUNSET_SCHEMA_PATHS)
    for relative_path in sorted(relative_paths):
        component_id = explicit_ids.get(relative_path)
        if component_id is None:
            component_id = _derived_component_id(relative_path)
        try:
            source = _read_packaged_component(relative_path)
        except Exception as exc:
            if isinstance(exc, CatalogIntegrityError):
                raise
            raise CatalogIntegrityError(
                f"unable to read mutation implementation component: {component_id}"
            ) from exc
        components.append(
            OperatorImplementationComponent(
                component_id=component_id,
                relative_path=relative_path,
                sha256=implementation_component_sha256(relative_path, source),
            )
        )
    return tuple(sorted(components, key=lambda item: (item.component_id, item.relative_path)))


def _packaged_python_component_paths() -> tuple[str, ...]:
    """Enumerate the complete installed first-party Python source closure."""

    def walk(directory: Traversable, prefix: str) -> Iterator[str]:
        for child in sorted(directory.iterdir(), key=lambda item: item.name):
            relative_path = f"{prefix}/{child.name}"
            if child.is_dir():
                if child.name != "__pycache__":
                    yield from walk(child, relative_path)
            elif child.is_file() and child.name.endswith(".py"):
                yield relative_path

    try:
        return tuple(walk(resources.files("agent_assure"), "agent_assure"))
    except Exception as exc:
        raise CatalogIntegrityError(
            "unable to enumerate packaged mutation implementation sources"
        ) from exc


def _derived_component_id(relative_path: str) -> str:
    if relative_path.startswith("agent_assure/") and relative_path.endswith(".py"):
        source_name = relative_path.removeprefix("agent_assure/").removesuffix(".py")
        return f"source.{source_name.replace('/', '.')}"
    if relative_path in _FROZEN_RUNSET_SCHEMA_PATHS:
        version = relative_path.split("/", maxsplit=2)[1].removeprefix("v")
        return f"schema.frozen.v{version}.run-set"
    raise CatalogIntegrityError(
        f"implementation component has no reviewed identity mapping: {relative_path}"
    )


def _target_control_creation_digest(
    operator_id: str,
    control_id: str,
) -> str:
    try:
        return _TARGET_CONTROL_CREATION_DIGESTS[(operator_id, control_id)]
    except KeyError as exc:
        raise CatalogIntegrityError(
            f"operator target has no authored creation-time digest: {operator_id}/{control_id}"
        ) from exc


def _introduction_components(
    operator_id: str,
) -> tuple[OperatorImplementationComponent, ...]:
    """Return the authored, immutable source snapshot for first introduction."""
    try:
        source = _read_packaged_component(_INTRODUCTION_SNAPSHOT_PATH)
        return introduction_components_from_source(operator_id, source)
    except CatalogIntegrityError:
        raise
    except Exception as exc:
        raise CatalogIntegrityError(
            f"operator has no authored introduction snapshot: {operator_id}"
        ) from exc


def introduction_components_from_source(
    operator_id: str,
    source: bytes,
) -> tuple[OperatorImplementationComponent, ...]:
    """Parse one operator's fail-closed authored introduction snapshot."""
    try:
        raw_document: object = json.loads(
            source.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
        if not isinstance(raw_document, dict):
            raise CatalogIntegrityError("introduction snapshot root is not an object")
        document = cast(dict[object, object], raw_document)
        if any(not isinstance(key, str) for key in document):
            raise CatalogIntegrityError("introduction snapshot has a non-string key")
        raw_components = document.get(operator_id)
        if not isinstance(raw_components, list) or not raw_components:
            raise CatalogIntegrityError(
                f"operator has no authored introduction snapshot: {operator_id}"
            )
        components: list[OperatorImplementationComponent] = []
        required_keys = {"component_id", "relative_path", "sha256"}
        for raw_component in raw_components:
            if not isinstance(raw_component, dict):
                raise CatalogIntegrityError("introduction component is not an object")
            component = cast(dict[object, object], raw_component)
            if set(component) != required_keys:
                raise CatalogIntegrityError(
                    "introduction component has an invalid field set"
                )
            component_id = component["component_id"]
            relative_path = component["relative_path"]
            sha256 = component["sha256"]
            if (
                not isinstance(component_id, str)
                or not isinstance(relative_path, str)
                or not isinstance(sha256, str)
            ):
                raise CatalogIntegrityError(
                    "introduction component fields must be strings"
                )
            components.append(
                OperatorImplementationComponent(
                    component_id=component_id,
                    relative_path=relative_path,
                    sha256=sha256,
                )
            )
        result = tuple(components)
        component_keys = tuple(
            (component.component_id, component.relative_path) for component in result
        )
        if component_keys != tuple(sorted(set(component_keys))):
            raise CatalogIntegrityError(
                "introduction components are not unique and canonically sorted"
            )
        if len({component.component_id for component in result}) != len(result):
            raise CatalogIntegrityError("introduction component IDs are not unique")
        if len({component.relative_path for component in result}) != len(result):
            raise CatalogIntegrityError("introduction component paths are not unique")
        return result
    except CatalogIntegrityError:
        raise
    except Exception as exc:
        raise CatalogIntegrityError(
            f"operator introduction snapshot is invalid: {operator_id}"
        ) from exc


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogIntegrityError(
                f"introduction snapshot has duplicate key: {key!r}"
            )
        result[key] = value
    return result


def _read_packaged_component(relative_path: str) -> bytes:
    if relative_path.startswith("agent_assure/"):
        component = resources.files("agent_assure")
        for part in relative_path.removeprefix("agent_assure/").split("/"):
            component = component.joinpath(part)
    elif relative_path in _FROZEN_RUNSET_SCHEMA_PATHS:
        repository_component = Path(__file__).resolve().parents[3] / relative_path
        if repository_component.is_file():
            try:
                return repository_component.read_bytes()
            except Exception as exc:
                raise CatalogIntegrityError(
                    "packaged mutation schema component is unreadable: "
                    f"{relative_path}"
                ) from exc
        component = resources.files("agent_assure.schema_resources")
        for part in relative_path.removeprefix("schemas/").split("/"):
            component = component.joinpath(part)
    else:
        raise CatalogIntegrityError("implementation component is outside reviewed roots")
    try:
        return component.read_bytes()
    except Exception as exc:
        raise CatalogIntegrityError(
            f"packaged mutation implementation component is unreadable: {relative_path}"
        ) from exc


def lf_normalized_sha256(source: bytes) -> str:
    """Hash source after canonicalizing CRLF and lone CR line endings to LF."""
    normalized_source = source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalized_source).hexdigest()


def implementation_component_sha256(relative_path: str, source: bytes) -> str:
    """Hash one implementation component with release-stamp normalization.

    The introduction commit is necessarily filled in after the implementation
    first has an immutable commit. That administrative stamp is normalized only
    for the catalog component so the follow-up provenance-only commit does not
    change the method identity it is authenticating. Every other catalog byte
    and every byte of every other component remains identity-bearing.
    """
    normalized_source = source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if relative_path == _CATALOG_COMPONENT_PATH:
        normalized_source = _INTRODUCTION_STAMP_PATTERN.sub(
            _NORMALIZED_INTRODUCTION_STAMP,
            normalized_source,
        )
    return hashlib.sha256(normalized_source).hexdigest()


@lru_cache(maxsize=1)
def _operator_catalog() -> tuple[RegisteredOperator, ...]:
    try:
        implementation_components = _implementation_components()
        catalog = tuple(
            sorted(
                (
                    _registered_operator(
                        operator_id="drop-material-evidence-link",
                        target_control_id="material_claims_have_evidence",
                        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                        permitted_changed_paths=("/runs/*/claim_evidence_links",),
                        preconditions=(
                            OperatorPrecondition(
                                precondition_id="fixture-mode",
                                summary="The source is a validated deterministic fixture RunSet.",
                            ),
                            OperatorPrecondition(
                                precondition_id="supported-material-claim",
                                summary=(
                                    "A declared material claim has at least one valid "
                                    "content-addressed evidence link."
                                ),
                            ),
                        ),
                        resolver=operators.drop_material_evidence_link_targets,
                        limitations=(
                            "The operator challenges one deterministically selected "
                            "material claim.",
                            "The finite operator does not represent every evidence-link failure.",
                        ),
                        implementation_components=implementation_components,
                    ),
                    _registered_operator(
                        operator_id="bypass-required-human-review",
                        target_control_id="human_review_required",
                        reason_code=ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT,
                        permitted_changed_paths=(
                            "/runs/*/human_review_performed",
                            "/runs/*/human_review_required",
                        ),
                        preconditions=(
                            OperatorPrecondition(
                                precondition_id="fixture-mode",
                                summary="The source is a validated deterministic fixture RunSet.",
                            ),
                            OperatorPrecondition(
                                precondition_id="completed-required-review",
                                summary=(
                                    "A case requires review and the source records both "
                                    "routing and completed review."
                                ),
                            ),
                        ),
                        resolver=operators.bypass_required_human_review_targets,
                        limitations=(
                            "The operator challenges one deterministically selected review route.",
                            "It does not assess the substantive quality of human review.",
                        ),
                        implementation_components=implementation_components,
                    ),
                    _registered_operator(
                        operator_id="inject-forbidden-tool",
                        target_control_id="tool_allowlist",
                        reason_code=ReasonCode.FORBIDDEN_TOOL,
                        permitted_changed_paths=("/runs/*/tools",),
                        preconditions=(
                            OperatorPrecondition(
                                precondition_id="fixture-mode",
                                summary="The source is a validated deterministic fixture RunSet.",
                            ),
                            OperatorPrecondition(
                                precondition_id="enforced-tool-boundary",
                                summary=(
                                    "A case declares a forbidden-tool rule or an effective tool "
                                    "allowlist."
                                ),
                            ),
                        ),
                        resolver=operators.inject_forbidden_tool_targets,
                        limitations=(
                            "The injected tool identifier is synthetic metadata; "
                            "no tool is executed.",
                            "The operator challenges one deterministically selected tool boundary.",
                        ),
                        implementation_components=implementation_components,
                    ),
                ),
                key=lambda item: item.descriptor.operator_id,
            )
        )
        operator_ids = tuple(item.descriptor.operator_id for item in catalog)
        if len(set(operator_ids)) != len(operator_ids):
            raise CatalogIntegrityError("built-in mutation operator IDs are not unique")
        return catalog
    except CatalogIntegrityError:
        raise
    except Exception as exc:
        raise CatalogIntegrityError(
            "built-in mutation catalog failed integrity validation"
        ) from exc
