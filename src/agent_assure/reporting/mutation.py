from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from agent_assure.canonical.jcs import canonical_bytes
from agent_assure.canonical.normalize import digest_projection
from agent_assure.mutation.execution import MutationExecution, build_evidence_descriptor
from agent_assure.schema.validation import validate_artifact_payload

MUTATION_RESULT_FILENAME = "assurance-mutation-result.json"
EVIDENCE_DESCRIPTOR_FILENAME = "assurance-evidence-descriptor.json"
MUTATED_RUNSET_FILENAME = "mutated-runset.json"

_FIXED_OUTPUT_FILENAMES = (
    MUTATION_RESULT_FILENAME,
    EVIDENCE_DESCRIPTOR_FILENAME,
    MUTATED_RUNSET_FILENAME,
)
_TRANSACTION_PREFIX = ".agent-assure-mutation-txn-"


@dataclass(frozen=True)
class MutationArtifactPaths:
    result: Path
    evidence_descriptor: Path
    mutated_runset: Path | None


def ensure_inputs_do_not_alias_mutation_output(
    source_inputs: Iterable[Path],
    out_dir: Path,
) -> None:
    """Reject any input alias to a fixed output through paths or file identity."""
    for source_input in source_inputs:
        source_identity = _resolved_path_identity(source_input, strict=True)
        for filename in _FIXED_OUTPUT_FILENAMES:
            destination = out_dir / filename
            destination_identity = _resolved_path_identity(destination, strict=False)
            if source_identity == destination_identity or _same_file(source_input, destination):
                raise ValueError("mutation input aliases a fixed mutation output path")


def write_mutation_artifacts(
    execution: MutationExecution,
    out_dir: Path,
    *,
    source_inputs: Iterable[Path] = (),
) -> MutationArtifactPaths:
    """Persist one complete canonical generation with rollback on commit failure."""
    _validate_execution_coherence(execution)
    result_payload = execution.result.model_dump(mode="json")
    descriptor_payload = execution.evidence_descriptor.model_dump(mode="json")
    validate_artifact_payload(result_payload, "assurance-mutation-result")
    validate_artifact_payload(
        descriptor_payload,
        "assurance-evidence-descriptor",
    )

    mutated_payload = execution.mutated_payload
    mutated_bytes: bytes | None = None
    if mutated_payload is not None:
        validate_artifact_payload(mutated_payload, "run-set")
        mutated_bytes = _canonical_json_bytes(mutated_payload)
        mutated_digest = hashlib.sha256(mutated_bytes).hexdigest()
        if mutated_digest != execution.result.mutated_digest:
            raise ValueError(
                "canonical mutated RunSet bytes do not match the mutation result digest"
            )
    elif execution.result.mutated_digest is not None:
        raise ValueError("mutation result references a transformed subject that is unavailable")

    generation = {
        MUTATION_RESULT_FILENAME: _canonical_json_bytes(result_payload),
        EVIDENCE_DESCRIPTOR_FILENAME: _canonical_json_bytes(descriptor_payload),
        MUTATED_RUNSET_FILENAME: mutated_bytes,
    }
    guarded_inputs = tuple(source_inputs)
    if guarded_inputs:
        ensure_inputs_do_not_alias_mutation_output(guarded_inputs, out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if guarded_inputs:
        # Recheck after directory creation; the transaction repeats this after
        # staging and immediately before it moves any destination entry.
        ensure_inputs_do_not_alias_mutation_output(guarded_inputs, out_dir)
    _replace_output_generation(out_dir, generation, source_inputs=guarded_inputs)

    return MutationArtifactPaths(
        result=out_dir / MUTATION_RESULT_FILENAME,
        evidence_descriptor=out_dir / EVIDENCE_DESCRIPTOR_FILENAME,
        mutated_runset=(out_dir / MUTATED_RUNSET_FILENAME if mutated_bytes is not None else None),
    )


def _validate_execution_coherence(execution: MutationExecution) -> None:
    result = execution.result
    descriptor = execution.evidence_descriptor
    if not any(dependency.digest == result.result_digest for dependency in descriptor.dependencies):
        raise ValueError("evidence descriptor does not depend on this mutation result digest")
    if descriptor.subject.digest != result.source_digest:
        raise ValueError("evidence descriptor subject does not bind the mutation source digest")
    if descriptor.method.method_id != result.evaluator_method_id:
        raise ValueError("evidence descriptor method does not bind the evaluator method ID")
    if descriptor.method.implementation_digest != result.evaluator_implementation_digest:
        raise ValueError(
            "evidence descriptor method does not bind the evaluator implementation digest"
        )
    if descriptor.method.implementation_version != result.evaluator_implementation_version:
        raise ValueError(
            "evidence descriptor method does not bind the evaluator implementation version"
        )
    expected_descriptor = build_evidence_descriptor(
        result,
        suite_digest=execution.suite_digest,
        generated_at=execution.generated_at,
    )
    if descriptor != expected_descriptor:
        raise ValueError(
            "evidence descriptor does not match the complete mutation result projection"
        )
    payload_present = execution.mutated_payload is not None
    digest_present = result.mutated_digest is not None
    if payload_present != digest_present:
        raise ValueError("mutated RunSet presence does not agree with the mutation result digest")


def _replace_output_generation(
    out_dir: Path,
    generation: dict[str, bytes | None],
    *,
    source_inputs: tuple[Path, ...],
) -> None:
    transaction_dir = Path(tempfile.mkdtemp(prefix=_TRANSACTION_PREFIX, dir=out_dir))
    staged = {
        filename: transaction_dir / f"new-{filename}"
        for filename, content in generation.items()
        if content is not None
    }
    backups = {filename: transaction_dir / f"old-{filename}" for filename in generation}
    preserve_recovery_material = False
    try:
        # No destination entry is touched until the complete new generation is
        # durable in same-filesystem staging files.
        for filename, stage_path in staged.items():
            content = generation[filename]
            if content is None:  # pragma: no cover - staged is derived above
                raise AssertionError("staged mutation output is missing content")
            _write_staged_file(stage_path, content)
        if source_inputs:
            ensure_inputs_do_not_alias_mutation_output(source_inputs, out_dir)

        moved_backups: dict[str, Path] = {}
        commit_started = False
        try:
            for filename, backup_path in backups.items():
                destination = out_dir / filename
                entry_kind = _entry_kind(destination)
                if entry_kind is None:
                    continue
                if entry_kind == "directory":
                    raise IsADirectoryError(
                        f"fixed mutation output path is a directory: {filename}"
                    )
                # Record intent before replace so rollback also covers a test or
                # platform failure raised immediately after the atomic move.
                moved_backups[filename] = backup_path
                _replace_entry(destination, backup_path)

            commit_started = True
            for filename, stage_path in staged.items():
                _replace_entry(stage_path, out_dir / filename)
            # A missing mutated payload deliberately leaves its fixed output
            # absent; any prior copy is now held in the backup set and removed
            # only after the generation committed successfully.
        except BaseException as exc:
            rollback_errors = _rollback_generation(
                out_dir,
                generation,
                moved_backups,
                commit_started=commit_started,
            )
            if rollback_errors:
                preserve_recovery_material = True
                detail = "; ".join(rollback_errors)
                raise OSError(
                    "mutation output transaction failed and rollback was incomplete: " + detail
                ) from exc
            raise
    finally:
        if not preserve_recovery_material:
            _cleanup_transaction_dir(transaction_dir, staged.values(), backups.values())


def _rollback_generation(
    out_dir: Path,
    generation: dict[str, bytes | None],
    moved_backups: dict[str, Path],
    *,
    commit_started: bool,
) -> tuple[str, ...]:
    errors: list[str] = []
    if commit_started:
        for filename, content in generation.items():
            if content is None:
                continue
            try:
                _unlink_entry(out_dir / filename)
            except OSError as exc:
                errors.append(f"remove {filename}: {type(exc).__name__}")
    for filename, backup_path in reversed(tuple(moved_backups.items())):
        if not _entry_exists(backup_path):
            continue
        try:
            _replace_entry(backup_path, out_dir / filename)
        except OSError as exc:
            errors.append(f"restore {filename}: {type(exc).__name__}")
    return tuple(errors)


def _write_staged_file(path: Path, content: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _replace_entry(source: Path, destination: Path) -> None:
    # os.replace renames the directory entry itself. Unlike opening a fixed
    # output path, it does not stream bytes through an existing symlink target.
    os.replace(source, destination)


def _cleanup_transaction_dir(
    transaction_dir: Path,
    staged_paths: Iterable[Path],
    backup_paths: Iterable[Path],
) -> None:
    for paths in (staged_paths, backup_paths):
        for path in paths:
            try:
                _unlink_entry(path)
            except OSError:
                pass
    try:
        transaction_dir.rmdir()
    except OSError:
        pass


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        return False


def _resolved_path_identity(path: Path, *, strict: bool) -> str:
    try:
        resolved = path.resolve(strict=strict)
    except RuntimeError as exc:
        raise ValueError("mutation artifact path cannot be safely resolved") from exc
    return os.path.normcase(os.path.abspath(resolved))


def _entry_kind(path: Path) -> str | None:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return None
    return "directory" if stat.S_ISDIR(mode) else "entry"


def _entry_exists(path: Path) -> bool:
    return _entry_kind(path) is not None


def _unlink_entry(path: Path) -> None:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    if stat.S_ISDIR(mode):
        raise IsADirectoryError(path)
    path.unlink()


def _canonical_json_bytes(value: object) -> bytes:
    return canonical_bytes(digest_projection(value))
