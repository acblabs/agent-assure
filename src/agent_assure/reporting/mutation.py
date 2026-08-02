from __future__ import annotations

import errno
import hashlib
import os
import stat
import tempfile
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from agent_assure.artifact_io import (
    ensure_unlinked_directory,
)
from agent_assure.canonical.jcs import canonical_bytes
from agent_assure.canonical.normalize import digest_projection
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_CONFIG_TEXT_BYTES,
    load_json_bytes_bounded,
    read_file_bounded,
)
from agent_assure.mutation.execution import MutationExecution, build_evidence_descriptor
from agent_assure.reporting.mutation_namespace import (
    assert_generation_namespace_exclusive,
)
from agent_assure.schema.validation import validate_artifact_payload

MUTATION_RESULT_FILENAME = "assurance-mutation-result.json"
EVIDENCE_DESCRIPTOR_FILENAME = "assurance-evidence-descriptor.json"
MUTATED_RUNSET_FILENAME = "mutated-runset.json"
MUTATION_GENERATION_MANIFEST_FILENAME = "mutation-generation-manifest.json"
MUTATION_OUTPUT_LOCK_FILENAME = ".agent-assure-mutation.lock"

_FIXED_OUTPUT_FILENAMES = (
    MUTATION_RESULT_FILENAME,
    EVIDENCE_DESCRIPTOR_FILENAME,
    MUTATED_RUNSET_FILENAME,
    MUTATION_GENERATION_MANIFEST_FILENAME,
)
_TRANSACTION_PREFIX = ".agent-assure-mutation-txn-"
_GENERATION_MANIFEST_CONTRACT = "AssuranceMutationArtifactGeneration/v1"
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_GENERATION_MANIFEST_BYTES = MAX_CONFIG_TEXT_BYTES
_MAX_MUTATED_RUNSET_BYTES = (2 * MAX_ARTIFACT_JSON_BYTES) + MAX_CONFIG_TEXT_BYTES
_MAX_SINGLE_GENERATION_BYTES = 64 * 1024 * 1024
_PROTECTED_OUTPUT_FILENAMES = (
    *_FIXED_OUTPUT_FILENAMES,
    MUTATION_OUTPUT_LOCK_FILENAME,
)


@dataclass(frozen=True)
class MutationArtifactPaths:
    result: Path
    evidence_descriptor: Path
    mutated_runset: Path | None
    generation_manifest: Path


def ensure_inputs_do_not_alias_mutation_output(
    source_inputs: Iterable[Path],
    out_dir: Path,
) -> None:
    """Reject any input alias to a fixed output through paths or file identity."""
    _ensure_mutation_output_directory_safe(out_dir)
    for source_input in source_inputs:
        source_identity = _resolved_path_identity(source_input, strict=True)
        for filename in _PROTECTED_OUTPUT_FILENAMES:
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
    _ensure_mutation_output_directory_safe(out_dir)
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

    artifact_generation = {
        MUTATION_RESULT_FILENAME: _canonical_json_bytes(result_payload),
        EVIDENCE_DESCRIPTOR_FILENAME: _canonical_json_bytes(descriptor_payload),
        MUTATED_RUNSET_FILENAME: mutated_bytes,
    }
    generation = {
        **artifact_generation,
        MUTATION_GENERATION_MANIFEST_FILENAME: _generation_manifest_bytes(artifact_generation),
    }
    guarded_inputs = tuple(source_inputs)
    if guarded_inputs:
        ensure_inputs_do_not_alias_mutation_output(guarded_inputs, out_dir)
    ensure_unlinked_directory(out_dir)
    if guarded_inputs:
        # Recheck after directory creation; the transaction repeats this after
        # staging and immediately before it moves any destination entry.
        ensure_inputs_do_not_alias_mutation_output(guarded_inputs, out_dir)
    ensure_unlinked_directory(out_dir)
    with _mutation_output_lock(out_dir):
        ensure_unlinked_directory(out_dir)
        assert_generation_namespace_exclusive(out_dir, namespace="single")
        if guarded_inputs:
            ensure_inputs_do_not_alias_mutation_output(guarded_inputs, out_dir)
        _replace_output_generation(out_dir, generation, source_inputs=guarded_inputs)
        _validate_mutation_artifact_generation_unlocked(out_dir)

    return MutationArtifactPaths(
        result=out_dir / MUTATION_RESULT_FILENAME,
        evidence_descriptor=out_dir / EVIDENCE_DESCRIPTOR_FILENAME,
        mutated_runset=(out_dir / MUTATED_RUNSET_FILENAME if mutated_bytes is not None else None),
        generation_manifest=out_dir / MUTATION_GENERATION_MANIFEST_FILENAME,
    )


def validate_mutation_artifact_generation(out_dir: Path) -> MutationArtifactPaths:
    """Validate one point-in-time generation and return its fixed paths."""
    with open_validated_mutation_artifact_generation(out_dir) as paths:
        return paths


@contextmanager
def open_validated_mutation_artifact_generation(
    out_dir: Path,
) -> Iterator[MutationArtifactPaths]:
    """Hold the writer lock while a caller validates and consumes one generation."""
    _ensure_mutation_output_directory_safe(out_dir)
    ensure_unlinked_directory(out_dir)
    with _mutation_output_lock(out_dir):
        assert_generation_namespace_exclusive(out_dir, namespace="single")
        yield _validate_mutation_artifact_generation_unlocked(out_dir)


def _validate_mutation_artifact_generation_unlocked(
    out_dir: Path,
) -> MutationArtifactPaths:
    """Validate fixed members while the caller holds the generation lock."""
    manifest_path = out_dir / MUTATION_GENERATION_MANIFEST_FILENAME
    manifest_contents = read_file_bounded(
        manifest_path,
        max_bytes=_MAX_GENERATION_MANIFEST_BYTES,
        label="mutation artifact generation manifest",
    )
    generation_bytes = len(manifest_contents.data)
    raw_manifest = load_json_bytes_bounded(
        manifest_contents.data,
        max_bytes=_MAX_GENERATION_MANIFEST_BYTES,
        label="mutation artifact generation manifest",
    )
    if not isinstance(raw_manifest, dict):
        raise ValueError("mutation artifact generation manifest must be an object")
    manifest = cast(dict[str, object], raw_manifest)
    if manifest.get("contract_id") != _GENERATION_MANIFEST_CONTRACT:
        raise ValueError("mutation artifact generation manifest contract is unsupported")
    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise ValueError("mutation artifact generation manifest has no artifact list")
    expected_filenames = (
        MUTATION_RESULT_FILENAME,
        EVIDENCE_DESCRIPTOR_FILENAME,
        MUTATED_RUNSET_FILENAME,
    )
    if len(raw_artifacts) != len(expected_filenames):
        raise ValueError("mutation artifact generation manifest is incomplete")
    projection = {
        "contract_id": _GENERATION_MANIFEST_CONTRACT,
        "artifacts": raw_artifacts,
    }
    if (
        manifest.get("generation_digest")
        != hashlib.sha256(_canonical_json_bytes(projection)).hexdigest()
    ):
        raise ValueError("mutation artifact generation manifest digest does not match")

    mutated_runset_present = False
    for filename, raw_entry in zip(expected_filenames, raw_artifacts, strict=True):
        if not isinstance(raw_entry, dict):
            raise ValueError("mutation artifact generation manifest entry must be an object")
        entry = cast(dict[str, object], raw_entry)
        if entry.get("filename") != filename:
            raise ValueError("mutation artifact generation manifest order is invalid")
        present = entry.get("present")
        digest = entry.get("sha256")
        if not isinstance(present, bool):
            raise ValueError("mutation artifact generation presence must be boolean")
        path = out_dir / filename
        if present:
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("mutation artifact generation digest is malformed")
            try:
                contents = read_file_bounded(
                    path,
                    max_bytes=(
                        _MAX_MUTATED_RUNSET_BYTES
                        if filename == MUTATED_RUNSET_FILENAME
                        else MAX_ARTIFACT_JSON_BYTES
                    ),
                    label=f"committed mutation artifact {filename}",
                )
            except FileNotFoundError as exc:
                raise ValueError(f"committed mutation artifact is missing: {filename}") from exc
            generation_bytes += len(contents.data)
            if generation_bytes > _MAX_SINGLE_GENERATION_BYTES:
                raise ValueError(
                    "mutation artifact generation exceeds maximum aggregate size"
                )
            if contents.sha256 != digest:
                raise ValueError(f"committed mutation artifact digest does not match: {filename}")
        elif digest is not None or _entry_exists(path):
            raise ValueError(f"mutation artifact generation absence does not match: {filename}")
        if filename == MUTATED_RUNSET_FILENAME:
            mutated_runset_present = present

    return MutationArtifactPaths(
        result=out_dir / MUTATION_RESULT_FILENAME,
        evidence_descriptor=out_dir / EVIDENCE_DESCRIPTOR_FILENAME,
        mutated_runset=(out_dir / MUTATED_RUNSET_FILENAME if mutated_runset_present else None),
        generation_manifest=manifest_path,
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
            commit_order = (
                *(
                    item
                    for item in staged.items()
                    if item[0] != MUTATION_GENERATION_MANIFEST_FILENAME
                ),
                *(
                    item
                    for item in staged.items()
                    if item[0] == MUTATION_GENERATION_MANIFEST_FILENAME
                ),
            )
            for filename, stage_path in commit_order:
                if filename == MUTATION_GENERATION_MANIFEST_FILENAME:
                    # The manifest is the single commit marker. Make directory
                    # updates for every member durable before publishing it.
                    _fsync_directory(out_dir)
                _replace_entry(stage_path, out_dir / filename)
            _fsync_directory(out_dir)
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


def _generation_manifest_bytes(generation: dict[str, bytes | None]) -> bytes:
    artifacts = [
        {
            "filename": filename,
            "present": content is not None,
            "sha256": hashlib.sha256(content).hexdigest() if content is not None else None,
        }
        for filename, content in generation.items()
    ]
    projection = {
        "contract_id": _GENERATION_MANIFEST_CONTRACT,
        "artifacts": artifacts,
    }
    return _canonical_json_bytes(
        {
            **projection,
            "generation_digest": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }
    )


@contextmanager
def _mutation_output_lock(out_dir: Path) -> Iterator[None]:
    lock_path = out_dir / MUTATION_OUTPUT_LOCK_FILENAME
    descriptor = _open_safe_lock_file(lock_path)
    with os.fdopen(descriptor, "r+b") as handle:
        _lock_file(handle)
        try:
            _assert_open_lock_identity(handle, lock_path)
            yield
        finally:
            _unlock_file(handle)


def _open_safe_lock_file(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise OSError("refusing unsafe mutation output lock path") from exc
        raise
    try:
        _assert_open_lock_identity_descriptor(descriptor, path)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _assert_open_lock_identity(handle: BinaryIO, path: Path) -> None:
    _assert_open_lock_identity_descriptor(handle.fileno(), path)


def _assert_open_lock_identity_descriptor(descriptor: int, path: Path) -> None:
    opened = os.fstat(descriptor)
    try:
        current = os.lstat(path)
    except FileNotFoundError as exc:
        raise OSError("mutation output lock path changed while opening") from exc
    attributes = getattr(current, "st_file_attributes", 0)
    if (
        stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        or current.st_nlink != 1
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise OSError("refusing unsafe mutation output lock path")


def _lock_file(handle: BinaryIO) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        locking = cast(Callable[[int, int, int], None], vars(msvcrt)["locking"])
        lock_ex = cast(int, vars(msvcrt)["LK_LOCK"])
        locking(handle.fileno(), lock_ex, 1)
        if os.fstat(handle.fileno()).st_size == 0:
            handle.seek(0)
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        return
    import fcntl

    flock = cast(Callable[[int, int], None], vars(fcntl)["flock"])
    lock_ex = cast(int, vars(fcntl)["LOCK_EX"])
    flock(handle.fileno(), lock_ex)


def _unlock_file(handle: BinaryIO) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        locking = cast(Callable[[int, int, int], None], vars(msvcrt)["locking"])
        lock_un = cast(int, vars(msvcrt)["LK_UNLCK"])
        locking(handle.fileno(), lock_un, 1)
        return
    import fcntl

    flock = cast(Callable[[int, int], None], vars(fcntl)["flock"])
    lock_un = cast(int, vars(fcntl)["LOCK_UN"])
    flock(handle.fileno(), lock_un)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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


def _ensure_mutation_output_directory_safe(out_dir: Path) -> None:
    try:
        resolved = out_dir.resolve(strict=False)
    except RuntimeError as exc:
        raise ValueError("mutation output directory cannot be safely resolved") from exc
    if resolved == Path(resolved.anchor):
        raise ValueError("mutation output directory must not be a filesystem root")


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
