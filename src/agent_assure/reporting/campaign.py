from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from agent_assure.artifact_io import ensure_unlinked_directory
from agent_assure.canonical.jcs import canonical_bytes
from agent_assure.canonical.normalize import digest_projection
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_CONFIG_TEXT_BYTES,
    BoundedFileContents,
    load_json_bytes_bounded,
    read_file_bounded,
)
from agent_assure.mutation.campaign import MutationCampaignExecution
from agent_assure.mutation.execution import build_evidence_descriptor
from agent_assure.reporting import mutation as _mutation_reporting
from agent_assure.reporting.mutation_namespace import (
    CAMPAIGN_OPERATOR_FILENAME_INDEX_LIMIT,
    assert_generation_namespace_exclusive,
    is_campaign_generation_filename,
    normalized_generation_filename,
)
from agent_assure.schema.campaign import (
    MAX_CAMPAIGN_OPERATORS,
    AssuranceMutationCampaign,
    AssuranceMutationCatalog,
)
from agent_assure.schema.mutation import (
    AssuranceEvidenceDescriptor,
    AssuranceMutationResult,
)
from agent_assure.schema.validation import validate_artifact_payload

MUTATION_CATALOG_FILENAME = "assurance-mutation-catalog.json"
MUTATION_CAMPAIGN_FILENAME = "assurance-mutation-campaign.json"
MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME = "mutation-campaign-generation-manifest.json"
MUTATION_CAMPAIGN_OUTPUT_LOCK_FILENAME = _mutation_reporting.MUTATION_OUTPUT_LOCK_FILENAME

_GENERATION_MANIFEST_CONTRACT = "AssuranceMutationCampaignArtifactGeneration/v1"
_TRANSACTION_PREFIX = ".agent-assure-mutation-campaign-txn-"
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ALIAS_GUARD_DIRECTORY_SCAN_LIMIT = 4096
_MAX_GENERATION_MANIFEST_BYTES = MAX_CONFIG_TEXT_BYTES
_MAX_MUTATED_RUNSET_BYTES = (2 * MAX_ARTIFACT_JSON_BYTES) + MAX_CONFIG_TEXT_BYTES
_MAX_CAMPAIGN_GENERATION_BYTES = 256 * 1024 * 1024
_GLOBAL_ARTIFACT_FILENAMES = (
    MUTATION_CATALOG_FILENAME,
    MUTATION_CAMPAIGN_FILENAME,
    MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME,
)


@dataclass(frozen=True)
class MutationCampaignOperatorArtifactPaths:
    index: int
    operator_id: str
    result: Path
    evidence_descriptor: Path
    mutated_runset: Path | None


@dataclass(frozen=True)
class MutationCampaignArtifactPaths:
    catalog: Path
    campaign: Path
    operator_artifacts: tuple[MutationCampaignOperatorArtifactPaths, ...]
    generation_manifest: Path


@dataclass(frozen=True)
class _ArtifactSpec:
    filename: str
    role: str
    operator_id: str | None
    present: bool


class _CampaignGenerationReader:
    """Cache bounded file snapshots and enforce one aggregate campaign budget."""

    def __init__(self) -> None:
        self._contents: dict[str, BoundedFileContents] = {}
        self._total_bytes = 0

    def read(
        self,
        path: Path,
        *,
        max_bytes: int,
        label: str,
    ) -> BoundedFileContents:
        key = normalized_generation_filename(path.name)
        cached = self._contents.get(key)
        if cached is not None:
            return cached
        contents = read_file_bounded(path, max_bytes=max_bytes, label=label)
        self._total_bytes += len(contents.data)
        if self._total_bytes > _MAX_CAMPAIGN_GENERATION_BYTES:
            raise ValueError("mutation campaign generation exceeds maximum aggregate size")
        self._contents[key] = contents
        return contents


def ensure_inputs_do_not_alias_mutation_campaign_output(
    source_inputs: Iterable[Path],
    out_dir: Path,
) -> None:
    """Reject lexical, resolved-path, and file-identity aliases to campaign outputs."""
    out_dir_identity = _ensure_campaign_output_directory_safe(out_dir)
    protected_filenames = _all_protected_output_filenames()
    protected_filename_set = frozenset(protected_filenames)
    destination_identities = frozenset(
        os.path.normcase(os.path.abspath(Path(out_dir_identity) / filename))
        for filename in protected_filenames
    )
    existing_destinations = _existing_protected_output_paths(
        out_dir,
        protected_filename_set,
    )
    for source_input in source_inputs:
        source_identity = _resolved_path_identity(source_input, strict=True)
        if source_identity in destination_identities or any(
            _same_file(source_input, destination) for destination in existing_destinations
        ):
            raise ValueError("mutation campaign input aliases a protected campaign output path")


def write_mutation_campaign_artifacts(
    execution: MutationCampaignExecution,
    out_dir: Path,
    *,
    source_inputs: Iterable[Path] = (),
) -> MutationCampaignArtifactPaths:
    """Persist one digest-bound campaign generation with rollback-safe publication."""
    _ensure_campaign_output_directory_safe(out_dir)
    _validate_execution_coherence(execution)

    catalog_payload = execution.catalog.model_dump(mode="json")
    campaign_payload = execution.campaign.model_dump(mode="json")
    validate_artifact_payload(catalog_payload, "assurance-mutation-catalog")
    validate_artifact_payload(campaign_payload, "assurance-mutation-campaign")

    specs: list[_ArtifactSpec] = [
        _ArtifactSpec(
            filename=MUTATION_CATALOG_FILENAME,
            role="catalog",
            operator_id=None,
            present=True,
        ),
        _ArtifactSpec(
            filename=MUTATION_CAMPAIGN_FILENAME,
            role="campaign",
            operator_id=None,
            present=True,
        ),
    ]
    artifacts: dict[str, bytes | None] = {
        MUTATION_CATALOG_FILENAME: _canonical_json_bytes(catalog_payload),
        MUTATION_CAMPAIGN_FILENAME: _canonical_json_bytes(campaign_payload),
    }
    operator_paths: list[MutationCampaignOperatorArtifactPaths] = []

    for index, operator_execution in enumerate(execution.operator_executions):
        operator_id = operator_execution.result.operator_id
        result_filename = _operator_artifact_filename(index, "mutation-result")
        descriptor_filename = _operator_artifact_filename(index, "evidence-descriptor")
        mutated_filename = _operator_artifact_filename(index, "mutated-runset")

        result_payload = operator_execution.result.model_dump(mode="json")
        descriptor_payload = operator_execution.evidence_descriptor.model_dump(mode="json")
        validate_artifact_payload(result_payload, "assurance-mutation-result")
        validate_artifact_payload(
            descriptor_payload,
            "assurance-evidence-descriptor",
        )
        result_bytes = _canonical_json_bytes(result_payload)
        descriptor_bytes = _canonical_json_bytes(descriptor_payload)

        mutated_payload = operator_execution.mutated_payload
        mutated_bytes: bytes | None = None
        if mutated_payload is not None:
            validate_artifact_payload(mutated_payload, "run-set")
            mutated_bytes = _canonical_json_bytes(mutated_payload)
            if (
                hashlib.sha256(mutated_bytes).hexdigest()
                != operator_execution.result.mutated_digest
            ):
                raise ValueError(
                    "canonical mutated RunSet bytes do not match the campaign result digest"
                )

        artifacts[result_filename] = result_bytes
        artifacts[descriptor_filename] = descriptor_bytes
        artifacts[mutated_filename] = mutated_bytes
        specs.extend(
            (
                _ArtifactSpec(
                    filename=result_filename,
                    role="mutation_result",
                    operator_id=operator_id,
                    present=True,
                ),
                _ArtifactSpec(
                    filename=descriptor_filename,
                    role="evidence_descriptor",
                    operator_id=operator_id,
                    present=True,
                ),
                _ArtifactSpec(
                    filename=mutated_filename,
                    role="mutated_runset",
                    operator_id=operator_id,
                    present=mutated_bytes is not None,
                ),
            )
        )
        operator_paths.append(
            MutationCampaignOperatorArtifactPaths(
                index=index,
                operator_id=operator_id,
                result=out_dir / result_filename,
                evidence_descriptor=out_dir / descriptor_filename,
                mutated_runset=(out_dir / mutated_filename if mutated_bytes is not None else None),
            )
        )

    generation = {
        **artifacts,
        MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME: _generation_manifest_bytes(
            catalog_digest=execution.catalog.catalog_digest,
            campaign_digest=execution.campaign.campaign_digest,
            specs=tuple(specs),
            artifacts=artifacts,
        ),
    }
    guarded_inputs = tuple(source_inputs)
    if guarded_inputs:
        ensure_inputs_do_not_alias_mutation_campaign_output(guarded_inputs, out_dir)
    ensure_unlinked_directory(out_dir)
    # Recheck after directory creation; the lock-scoped and post-staging checks
    # below cover the remaining publication race boundaries.
    if guarded_inputs:
        ensure_inputs_do_not_alias_mutation_campaign_output(guarded_inputs, out_dir)
    ensure_unlinked_directory(out_dir)

    # Campaign and single-mutation writers intentionally share the same lock so
    # readers never observe two writers mutating one output directory concurrently.
    with _mutation_reporting._mutation_output_lock(out_dir):
        ensure_unlinked_directory(out_dir)
        assert_generation_namespace_exclusive(out_dir, namespace="campaign")
        if guarded_inputs:
            ensure_inputs_do_not_alias_mutation_campaign_output(guarded_inputs, out_dir)
        _replace_output_generation(
            out_dir,
            generation,
            source_inputs=guarded_inputs,
        )
        _validate_mutation_campaign_artifact_generation_unlocked(out_dir)

    return MutationCampaignArtifactPaths(
        catalog=out_dir / MUTATION_CATALOG_FILENAME,
        campaign=out_dir / MUTATION_CAMPAIGN_FILENAME,
        operator_artifacts=tuple(operator_paths),
        generation_manifest=out_dir / MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME,
    )


def validate_mutation_campaign_artifact_generation(
    out_dir: Path,
) -> MutationCampaignArtifactPaths:
    """Validate a complete committed campaign generation."""
    with open_validated_mutation_campaign_artifact_generation(out_dir) as paths:
        return paths


@contextmanager
def open_validated_mutation_campaign_artifact_generation(
    out_dir: Path,
) -> Iterator[MutationCampaignArtifactPaths]:
    """Hold the output lock while validating and consuming one campaign generation."""
    _ensure_campaign_output_directory_safe(out_dir)
    ensure_unlinked_directory(out_dir)
    with _mutation_reporting._mutation_output_lock(out_dir):
        assert_generation_namespace_exclusive(out_dir, namespace="campaign")
        yield _validate_mutation_campaign_artifact_generation_unlocked(out_dir)


def _validate_mutation_campaign_artifact_generation_unlocked(
    out_dir: Path,
) -> MutationCampaignArtifactPaths:
    manifest_path = out_dir / MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME
    reader = _CampaignGenerationReader()
    manifest_contents = reader.read(
        manifest_path,
        max_bytes=_MAX_GENERATION_MANIFEST_BYTES,
        label="mutation campaign artifact generation manifest",
    )
    manifest = load_json_bytes_bounded(
        manifest_contents.data,
        max_bytes=_MAX_GENERATION_MANIFEST_BYTES,
        label="mutation campaign artifact generation manifest",
    )
    if not isinstance(manifest, dict):
        raise ValueError("mutation campaign generation manifest must be an object")
    expected_manifest_keys = {
        "contract_id",
        "catalog_digest",
        "campaign_digest",
        "artifacts",
        "generation_digest",
    }
    if set(manifest) != expected_manifest_keys:
        raise ValueError("mutation campaign generation manifest fields are invalid")
    if manifest.get("contract_id") != _GENERATION_MANIFEST_CONTRACT:
        raise ValueError("mutation campaign generation manifest contract is unsupported")
    catalog_digest = _required_digest(manifest.get("catalog_digest"), label="catalog")
    campaign_digest = _required_digest(manifest.get("campaign_digest"), label="campaign")
    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise ValueError("mutation campaign generation manifest has no artifact list")
    if len(raw_artifacts) > 2 + (3 * MAX_CAMPAIGN_OPERATORS):
        raise ValueError("mutation campaign generation manifest has too many artifacts")
    projection = {
        "contract_id": _GENERATION_MANIFEST_CONTRACT,
        "catalog_digest": catalog_digest,
        "campaign_digest": campaign_digest,
        "artifacts": raw_artifacts,
    }
    if (
        manifest.get("generation_digest")
        != hashlib.sha256(_canonical_json_bytes(projection)).hexdigest()
    ):
        raise ValueError("mutation campaign generation manifest digest does not match")

    catalog_contents = reader.read(
        out_dir / MUTATION_CATALOG_FILENAME,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="assurance mutation catalog",
    )
    campaign_contents = reader.read(
        out_dir / MUTATION_CAMPAIGN_FILENAME,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="assurance mutation campaign",
    )
    catalog_payload = load_json_bytes_bounded(
        catalog_contents.data,
        label="assurance mutation catalog",
    )
    campaign_payload = load_json_bytes_bounded(
        campaign_contents.data,
        label="assurance mutation campaign",
    )
    validate_artifact_payload(catalog_payload, "assurance-mutation-catalog")
    validate_artifact_payload(campaign_payload, "assurance-mutation-campaign")
    catalog = AssuranceMutationCatalog.model_validate(catalog_payload)
    campaign = AssuranceMutationCampaign.model_validate(campaign_payload)
    if catalog.catalog_digest != catalog_digest:
        raise ValueError("campaign generation catalog digest is not bound to its catalog")
    if campaign.campaign_digest != campaign_digest:
        raise ValueError("campaign generation campaign digest is not bound to its campaign")
    _validate_catalog_campaign_binding(catalog, campaign)

    expected_specs = _specs_for_campaign(campaign)
    entries = tuple(
        _parse_manifest_entry(raw_entry) for raw_entry in cast(list[object], raw_artifacts)
    )
    if len(entries) != len(expected_specs):
        raise ValueError("mutation campaign generation manifest is incomplete")

    for expected, entry in zip(expected_specs, entries, strict=True):
        filename, role, operator_id, present, digest = entry
        if (
            filename != expected.filename
            or role != expected.role
            or operator_id != expected.operator_id
            or present is not expected.present
        ):
            raise ValueError("mutation campaign generation artifact order is invalid")
        artifact_path = out_dir / filename
        if present:
            required_digest = _required_digest(digest, label="artifact")
            try:
                contents = reader.read(
                    artifact_path,
                    max_bytes=(
                        _MAX_MUTATED_RUNSET_BYTES
                        if expected.role == "mutated_runset"
                        else MAX_ARTIFACT_JSON_BYTES
                    ),
                    label=f"committed mutation campaign artifact {filename}",
                )
            except FileNotFoundError as exc:
                raise ValueError(
                    f"committed mutation campaign artifact is missing: {filename}"
                ) from exc
            if contents.sha256 != required_digest:
                raise ValueError(
                    f"committed mutation campaign artifact digest does not match: {filename}"
                )
        elif digest is not None or _mutation_reporting._entry_exists(artifact_path):
            raise ValueError(f"mutation campaign artifact absence does not match: {filename}")

    expected_names = {
        normalized_generation_filename(expected.filename)
        for expected in expected_specs
        if expected.present
    }
    for child in out_dir.iterdir():
        if (
            _is_campaign_artifact_filename(child.name)
            and normalized_generation_filename(child.name) not in expected_names
            and normalized_generation_filename(child.name)
            != normalized_generation_filename(MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME)
        ):
            raise ValueError(f"unexpected mutation campaign artifact is present: {child.name}")

    operator_paths: list[MutationCampaignOperatorArtifactPaths] = []
    for index, campaign_entry in enumerate(campaign.operator_results):
        result_path = out_dir / _operator_artifact_filename(index, "mutation-result")
        descriptor_path = out_dir / _operator_artifact_filename(
            index,
            "evidence-descriptor",
        )
        mutated_path = out_dir / _operator_artifact_filename(index, "mutated-runset")

        result_contents = reader.read(
            result_path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label=f"mutation campaign result {index}",
        )
        descriptor_contents = reader.read(
            descriptor_path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label=f"mutation campaign evidence descriptor {index}",
        )
        result_payload = load_json_bytes_bounded(
            result_contents.data,
            label=f"mutation campaign result {index}",
        )
        descriptor_payload = load_json_bytes_bounded(
            descriptor_contents.data,
            label=f"mutation campaign evidence descriptor {index}",
        )
        validate_artifact_payload(result_payload, "assurance-mutation-result")
        validate_artifact_payload(
            descriptor_payload,
            "assurance-evidence-descriptor",
        )
        result = AssuranceMutationResult.model_validate(result_payload)
        descriptor = AssuranceEvidenceDescriptor.model_validate(descriptor_payload)
        if result != campaign_entry.result:
            raise ValueError(
                "individual mutation result does not match its embedded campaign result"
            )
        _validate_result_descriptor_coherence(
            result,
            descriptor,
            suite_digest=campaign.suite_digest,
        )

        persisted_mutated_path: Path | None = None
        if result.mutated_digest is not None:
            mutated_contents = reader.read(
                mutated_path,
                max_bytes=_MAX_MUTATED_RUNSET_BYTES,
                label=f"mutation campaign mutated RunSet {index}",
            )
            mutated_payload = load_json_bytes_bounded(
                mutated_contents.data,
                max_bytes=_MAX_MUTATED_RUNSET_BYTES,
                label=f"mutation campaign mutated RunSet {index}",
            )
            validate_artifact_payload(mutated_payload, "run-set")
            if hashlib.sha256(_canonical_json_bytes(mutated_payload)).hexdigest() != (
                result.mutated_digest
            ):
                raise ValueError(
                    "persisted campaign mutated RunSet does not match its result digest"
                )
            persisted_mutated_path = mutated_path

        operator_paths.append(
            MutationCampaignOperatorArtifactPaths(
                index=index,
                operator_id=campaign_entry.operator_id,
                result=result_path,
                evidence_descriptor=descriptor_path,
                mutated_runset=persisted_mutated_path,
            )
        )

    return MutationCampaignArtifactPaths(
        catalog=out_dir / MUTATION_CATALOG_FILENAME,
        campaign=out_dir / MUTATION_CAMPAIGN_FILENAME,
        operator_artifacts=tuple(operator_paths),
        generation_manifest=manifest_path,
    )


def _validate_execution_coherence(execution: MutationCampaignExecution) -> None:
    catalog = execution.catalog
    campaign = execution.campaign
    _validate_catalog_campaign_binding(catalog, campaign)
    if len(execution.operator_executions) != len(campaign.operator_results):
        raise ValueError("campaign executions do not match the campaign result count")

    for campaign_entry, operator_execution in zip(
        campaign.operator_results,
        execution.operator_executions,
        strict=True,
    ):
        if operator_execution.result != campaign_entry.result:
            raise ValueError(
                "campaign execution result does not match its embedded campaign result"
            )
        if operator_execution.suite_digest != campaign.suite_digest:
            raise ValueError("campaign execution is bound to a different suite digest")
        _validate_result_descriptor_coherence(
            operator_execution.result,
            operator_execution.evidence_descriptor,
            suite_digest=operator_execution.suite_digest,
            generated_at=operator_execution.generated_at,
        )
        payload_present = operator_execution.mutated_payload is not None
        digest_present = operator_execution.result.mutated_digest is not None
        if payload_present != digest_present:
            raise ValueError(
                "campaign mutated RunSet presence does not agree with its result digest"
            )


def _validate_catalog_campaign_binding(
    catalog: AssuranceMutationCatalog,
    campaign: AssuranceMutationCampaign,
) -> None:
    if (
        campaign.catalog_id != catalog.catalog_id
        or campaign.catalog_digest != catalog.catalog_digest
    ):
        raise ValueError("mutation campaign is not bound to the persisted catalog")
    catalog_order = tuple(item.descriptor.operator_id for item in catalog.operators)
    if campaign.canonical_operator_order != catalog_order:
        raise ValueError("mutation campaign operator order does not match its catalog")
    catalog_by_id = {item.descriptor.operator_id: item for item in catalog.operators}
    for entry in campaign.operator_results:
        catalog_operator = catalog_by_id.get(entry.operator_id)
        if catalog_operator is None:
            raise ValueError("mutation campaign result references an operator outside its catalog")
        if entry.invariant_family != catalog_operator.invariant_family:
            raise ValueError("mutation campaign invariant family does not match its catalog")
        descriptor = catalog_operator.descriptor
        if entry.expected_detection_contract != (descriptor.expected_detection_contract):
            raise ValueError("mutation campaign expected detector does not match its catalog")
        result = entry.result
        if (
            result.operator_version != descriptor.operator_version
            or result.operator_digest != descriptor.operator_digest
            or result.implementation_digest != descriptor.implementation_digest
            or result.provenance != descriptor.provenance
            or result.independence_class is not descriptor.independence_class
        ):
            raise ValueError(
                "mutation campaign result identity does not match its catalog operator"
            )


def _validate_result_descriptor_coherence(
    result: AssuranceMutationResult,
    descriptor: AssuranceEvidenceDescriptor,
    *,
    suite_digest: str,
    generated_at: str | None = None,
) -> None:
    if not any(dependency.digest == result.result_digest for dependency in descriptor.dependencies):
        raise ValueError("campaign evidence descriptor does not depend on its result")
    if descriptor.subject.digest != result.source_digest:
        raise ValueError("campaign evidence descriptor is bound to another source")
    expected = build_evidence_descriptor(
        result,
        suite_digest=suite_digest,
        generated_at=generated_at or descriptor.validity.generated_at,
    )
    if descriptor != expected:
        raise ValueError(
            "campaign evidence descriptor does not match its mutation result projection"
        )


def _specs_for_campaign(
    campaign: AssuranceMutationCampaign,
) -> tuple[_ArtifactSpec, ...]:
    specs: list[_ArtifactSpec] = [
        _ArtifactSpec(MUTATION_CATALOG_FILENAME, "catalog", None, True),
        _ArtifactSpec(MUTATION_CAMPAIGN_FILENAME, "campaign", None, True),
    ]
    for index, entry in enumerate(campaign.operator_results):
        specs.extend(
            (
                _ArtifactSpec(
                    _operator_artifact_filename(index, "mutation-result"),
                    "mutation_result",
                    entry.operator_id,
                    True,
                ),
                _ArtifactSpec(
                    _operator_artifact_filename(index, "evidence-descriptor"),
                    "evidence_descriptor",
                    entry.operator_id,
                    True,
                ),
                _ArtifactSpec(
                    _operator_artifact_filename(index, "mutated-runset"),
                    "mutated_runset",
                    entry.operator_id,
                    entry.result.mutated_digest is not None,
                ),
            )
        )
    return tuple(specs)


def _generation_manifest_bytes(
    *,
    catalog_digest: str,
    campaign_digest: str,
    specs: tuple[_ArtifactSpec, ...],
    artifacts: Mapping[str, bytes | None],
) -> bytes:
    artifact_entries = [
        {
            "filename": spec.filename,
            "role": spec.role,
            "operator_id": spec.operator_id,
            "present": spec.present,
            "sha256": (
                hashlib.sha256(content).hexdigest()
                if (content := artifacts.get(spec.filename)) is not None
                else None
            ),
        }
        for spec in specs
    ]
    projection = {
        "contract_id": _GENERATION_MANIFEST_CONTRACT,
        "catalog_digest": catalog_digest,
        "campaign_digest": campaign_digest,
        "artifacts": artifact_entries,
    }
    return _canonical_json_bytes(
        {
            **projection,
            "generation_digest": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }
    )


def _parse_manifest_entry(
    raw_entry: object,
) -> tuple[str, str, str | None, bool, object]:
    if not isinstance(raw_entry, dict):
        raise ValueError("mutation campaign generation entry must be an object")
    entry = cast(dict[str, object], raw_entry)
    if set(entry) != {"filename", "role", "operator_id", "present", "sha256"}:
        raise ValueError("mutation campaign generation entry fields are invalid")
    filename = entry.get("filename")
    role = entry.get("role")
    operator_id = entry.get("operator_id")
    present = entry.get("present")
    if not isinstance(filename, str) or not _is_campaign_artifact_filename(filename):
        raise ValueError("mutation campaign generation filename is invalid")
    if not isinstance(role, str):
        raise ValueError("mutation campaign generation role is invalid")
    if operator_id is not None and not isinstance(operator_id, str):
        raise ValueError("mutation campaign generation operator ID is invalid")
    if not isinstance(present, bool):
        raise ValueError("mutation campaign generation presence must be boolean")
    return filename, role, operator_id, present, entry.get("sha256")


def _replace_output_generation(
    out_dir: Path,
    generation: dict[str, bytes | None],
    *,
    source_inputs: tuple[Path, ...],
) -> None:
    current_names = {
        child.name for child in out_dir.iterdir() if _is_campaign_artifact_filename(child.name)
    }
    complete_generation = {
        filename: generation.get(filename) for filename in sorted(current_names | set(generation))
    }
    transaction_dir = Path(tempfile.mkdtemp(prefix=_TRANSACTION_PREFIX, dir=out_dir))
    staged = {
        filename: transaction_dir / f"new-{filename}"
        for filename, content in complete_generation.items()
        if content is not None
    }
    backups = {filename: transaction_dir / f"old-{filename}" for filename in complete_generation}
    preserve_recovery_material = False
    try:
        for filename, stage_path in staged.items():
            content = complete_generation[filename]
            if content is None:  # pragma: no cover - staged is derived above
                raise AssertionError("staged campaign output is missing content")
            _mutation_reporting._write_staged_file(stage_path, content)
        if source_inputs:
            ensure_inputs_do_not_alias_mutation_campaign_output(
                source_inputs,
                out_dir,
            )

        moved_backups: dict[str, Path] = {}
        commit_started = False
        try:
            for filename, backup_path in backups.items():
                destination = out_dir / filename
                entry_kind = _mutation_reporting._entry_kind(destination)
                if entry_kind is None:
                    continue
                if entry_kind == "directory":
                    raise IsADirectoryError(
                        f"fixed mutation campaign output path is a directory: {filename}"
                    )
                moved_backups[filename] = backup_path
                _mutation_reporting._replace_entry(destination, backup_path)

            commit_started = True
            commit_order = (
                *(
                    item
                    for item in staged.items()
                    if item[0] != MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME
                ),
                *(
                    item
                    for item in staged.items()
                    if item[0] == MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME
                ),
            )
            for filename, stage_path in commit_order:
                if filename == MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME:
                    _mutation_reporting._fsync_directory(out_dir)
                _mutation_reporting._replace_entry(
                    stage_path,
                    out_dir / filename,
                )
            _mutation_reporting._fsync_directory(out_dir)
        except BaseException as exc:
            rollback_errors = _rollback_generation(
                out_dir,
                complete_generation,
                moved_backups,
                commit_started=commit_started,
            )
            if rollback_errors:
                preserve_recovery_material = True
                detail = "; ".join(rollback_errors)
                raise OSError(
                    "mutation campaign output transaction failed and rollback "
                    f"was incomplete: {detail}"
                ) from exc
            raise
    finally:
        if not preserve_recovery_material:
            _mutation_reporting._cleanup_transaction_dir(
                transaction_dir,
                staged.values(),
                backups.values(),
            )


def _rollback_generation(
    out_dir: Path,
    generation: Mapping[str, bytes | None],
    moved_backups: Mapping[str, Path],
    *,
    commit_started: bool,
) -> tuple[str, ...]:
    errors: list[str] = []
    if commit_started:
        for filename, content in generation.items():
            if content is None:
                continue
            try:
                _mutation_reporting._unlink_entry(out_dir / filename)
            except OSError as exc:
                errors.append(f"remove {filename}: {type(exc).__name__}")
    for filename, backup_path in reversed(tuple(moved_backups.items())):
        if not _mutation_reporting._entry_exists(backup_path):
            continue
        try:
            _mutation_reporting._replace_entry(
                backup_path,
                out_dir / filename,
            )
        except OSError as exc:
            errors.append(f"restore {filename}: {type(exc).__name__}")
    return tuple(errors)


def _operator_artifact_filename(index: int, kind: str) -> str:
    if index < 0 or index >= MAX_CAMPAIGN_OPERATORS:
        raise ValueError("mutation campaign operator index is out of range")
    if kind not in {
        "mutation-result",
        "evidence-descriptor",
        "mutated-runset",
    }:
        raise ValueError("mutation campaign artifact kind is invalid")
    return f"operator-{index:03d}-{kind}.json"


def _all_protected_output_filenames() -> tuple[str, ...]:
    operator_filenames = tuple(
        f"operator-{index:03d}-{kind}.json"
        for index in range(CAMPAIGN_OPERATOR_FILENAME_INDEX_LIMIT)
        for kind in (
            "mutation-result",
            "evidence-descriptor",
            "mutated-runset",
        )
    )
    return (
        *_GLOBAL_ARTIFACT_FILENAMES,
        MUTATION_CAMPAIGN_OUTPUT_LOCK_FILENAME,
        *operator_filenames,
    )


def _is_campaign_artifact_filename(filename: str) -> bool:
    return is_campaign_generation_filename(filename)


def _required_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"mutation campaign generation {label} digest is malformed")
    return value


def _ensure_campaign_output_directory_safe(out_dir: Path) -> str:
    try:
        resolved = out_dir.resolve(strict=False)
    except RuntimeError as exc:
        raise ValueError("mutation campaign output directory cannot be safely resolved") from exc
    if resolved == Path(resolved.anchor):
        raise ValueError("mutation campaign output directory must not be a filesystem root")
    return os.path.normcase(os.path.abspath(resolved))


def _existing_protected_output_paths(
    out_dir: Path,
    protected_filenames: frozenset[str],
) -> tuple[Path, ...]:
    canonical_by_casefold = {filename.casefold(): filename for filename in protected_filenames}
    try:
        existing: list[Path] = []
        with os.scandir(out_dir) as entries:
            for index, entry in enumerate(entries):
                if index >= _ALIAS_GUARD_DIRECTORY_SCAN_LIMIT:
                    return tuple(
                        out_dir / filename
                        for filename in sorted(protected_filenames)
                        if _mutation_reporting._entry_exists(out_dir / filename)
                    )
                canonical_filename = canonical_by_casefold.get(entry.name.casefold())
                if canonical_filename is None:
                    continue
                canonical_path = out_dir / canonical_filename
                if entry.name == canonical_filename or _mutation_reporting._entry_exists(
                    canonical_path
                ):
                    existing.append(canonical_path)
        return tuple(sorted(set(existing), key=lambda entry: entry.name))
    except FileNotFoundError:
        return ()


def _resolved_path_identity(path: Path, *, strict: bool) -> str:
    try:
        resolved = path.resolve(strict=strict)
    except RuntimeError as exc:
        raise ValueError("mutation campaign artifact path cannot be safely resolved") from exc
    return os.path.normcase(os.path.abspath(resolved))


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        return False


def _canonical_json_bytes(value: object) -> bytes:
    return canonical_bytes(digest_projection(value))
