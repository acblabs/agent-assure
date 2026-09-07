"""Shared, fail-closed publication primitives for CLI authoring commands.

The RAG and real-model-study command trees both finalize immutable JSON
artifacts.  Keeping the implementation here avoids a circular dependency
between those command modules while preserving one lock-coordinated,
no-clobber publication contract with identity-bound rollback after
recoverable failures.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel

from agent_assure.artifact_io import ensure_unlinked_directory
from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES
from agent_assure.live.config import LiveRunConfig
from agent_assure.rooted_io import (
    PinnedDirectoryFile,
    RootedDirectoryDescriptor,
    acquire_publication_lock,
    open_rooted_directory,
    release_publication_lock,
)


@dataclass
class _CreatedFinalizeOutput:
    lease: RootedDirectoryDescriptor
    name: str
    device: int
    inode: int
    descriptor: int


@dataclass
class _FinalizeOutputLock:
    lease: RootedDirectoryDescriptor
    name: str
    device: int
    inode: int
    descriptor: int
    locked: bool = False


def reject_inline_environment_for_finalization(
    config: LiveRunConfig,
    *,
    arm_name: str,
) -> None:
    """Prevent raw environment values from entering published live configs."""

    if config.adapter.script_env:
        raise ValueError(
            f"{arm_name} live config contains inline script_env values; "
            "configuration finalization refuses to persist them; use "
            "script_env_allowlist for runtime environment injection"
        )


def ensure_output_does_not_alias_inputs(
    *,
    out: Path,
    inputs: tuple[Path, ...],
    input_directories: tuple[Path, ...] = (),
) -> None:
    """Reject output roots that alias or contain immutable authoring inputs."""

    try:
        resolved_out = out.resolve(strict=False)
        resolved_inputs = tuple(path.resolve(strict=True) for path in inputs)
        resolved_directories = tuple(path.resolve(strict=True) for path in input_directories)
    except (OSError, RuntimeError) as exc:
        raise ValueError("input or output path cannot be safely resolved") from exc
    if resolved_out == Path(resolved_out.anchor):
        raise ValueError("output must not be a filesystem root")
    if any(resolved_out == source or same_file(resolved_out, source) for source in resolved_inputs):
        raise ValueError("output aliases an input artifact")
    if any(
        is_within(resolved_out, directory) or is_within(directory, resolved_out)
        for directory in resolved_directories
    ):
        raise ValueError("output overlaps an input run directory")


def ensure_finalize_paths(
    *,
    inputs: tuple[Path, ...],
    outputs: tuple[Path, ...],
    config_output_pairs: tuple[tuple[Path, Path], ...],
) -> None:
    """Validate immutable finalize inputs and distinct sibling JSON outputs."""

    try:
        resolved_inputs = tuple(path.resolve(strict=True) for path in inputs)
        resolved_outputs = tuple(path.resolve(strict=False) for path in outputs)
    except (OSError, RuntimeError) as exc:
        raise ValueError("finalize input or output path cannot be safely resolved") from exc
    if any(path.suffix.lower() != ".json" for path in resolved_outputs):
        raise ValueError("finalize outputs must use the .json suffix")
    normalized_outputs = tuple(os.path.normcase(os.path.abspath(path)) for path in resolved_outputs)
    if len(set(normalized_outputs)) != len(normalized_outputs):
        raise ValueError("finalize output paths must be distinct")
    if any(output == Path(output.anchor) or not output.name for output in resolved_outputs):
        raise ValueError("finalize outputs must name non-root files")
    if any(
        output == source or same_file(output, source)
        for output in resolved_outputs
        for source in resolved_inputs
    ):
        raise ValueError("finalize output aliases an authoring input")
    for source, output in config_output_pairs:
        try:
            source_parent = source.parent.resolve(strict=True)
            output_parent = output.parent.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError("finalized config output parent cannot be safely resolved") from exc
        if source_parent != output_parent or same_file(source, output):
            raise ValueError(
                "each finalized config must use a distinct filename beside its uncommitted input"
            )


def bounded_model_json(model: BaseModel, *, label: str) -> str:
    """Render a model as bounded, deterministic, human-readable JSON."""

    rendered = (
        json.dumps(
            model.model_dump(mode="json", warnings="error"),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if len(rendered.encode("utf-8")) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError(f"{label} exceeds the maximum supported size")
    return rendered


def publish_finalize_outputs(
    outputs: tuple[tuple[Path, str, str], ...],
    *,
    lock_root: Path | None = None,
) -> None:
    """Publish no-clobber outputs while holding locks for every final path.

    By default each persistent advisory lock lives beside its output. Callers
    publishing into a closed-inventory directory may supply an existing
    external lock root.
    """

    parent_leases: dict[str, RootedDirectoryDescriptor] = {}
    prepared: list[tuple[Path, bytes, str, RootedDirectoryDescriptor, str]] = []
    created: list[_CreatedFinalizeOutput] = []
    verification_pins: list[PinnedDirectoryFile] = []
    output_locks: list[_FinalizeOutputLock] = []
    completed = False
    try:
        for path, text, label in outputs:
            payload = text.encode("utf-8")
            parent = ensure_unlinked_directory(path.parent).resolve(strict=True)
            parent_key = os.path.normcase(os.path.abspath(parent))
            lease = parent_leases.get(parent_key)
            if lease is None:
                lease = open_rooted_directory(
                    parent,
                    ".",
                    label="finalize output parent",
                )
                parent_leases[parent_key] = lease
            prepared.append((path, payload, label, lease, path.name))

        lock_lease = None
        if lock_root is not None:
            resolved_lock_root = ensure_unlinked_directory(lock_root).resolve(strict=True)
            lock_root_key = os.path.normcase(os.path.abspath(resolved_lock_root))
            lock_lease = parent_leases.get(lock_root_key)
            if lock_lease is None:
                lock_lease = open_rooted_directory(
                    resolved_lock_root,
                    ".",
                    label="finalize output lock parent",
                )
                parent_leases[lock_root_key] = lock_lease

        output_locks = _acquire_finalize_output_locks(
            prepared,
            lock_lease=lock_lease,
        )

        absent: list[tuple[Path, bytes, str, RootedDirectoryDescriptor, str]] = []
        for item in prepared:
            _path, payload, label, lease, name = item
            try:
                opened = lease.open_file_bounded(
                    name,
                    max_bytes=MAX_ARTIFACT_JSON_BYTES,
                    label=label,
                    require_single_link=True,
                )
            except FileNotFoundError:
                absent.append(item)
                continue
            with opened:
                if opened.contents.data != payload:
                    raise ValueError(f"{label} output already exists with different content")

        for _path, payload, label, lease, name in absent:
            descriptor, metadata = lease.open_regular_file_exclusive_with_metadata(
                name,
                mode=0o600,
            )
            new_output = _CreatedFinalizeOutput(
                lease=lease,
                name=name,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                descriptor=descriptor,
            )
            created.append(new_output)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if _read_exact_descriptor(descriptor, len(payload)) != payload:
                raise OSError(f"{label} changed during publication")

        created_by_entry = {(id(item.lease), item.name): item for item in created}
        for _path, payload, label, lease, name in prepared:
            matched_output = created_by_entry.get((id(lease), name))
            if matched_output is not None:
                _verify_created_finalize_output(matched_output, payload, label=label)
                continue
            opened = lease.open_file_bounded(
                name,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label=label,
                require_single_link=True,
            )
            verification_pins.append(opened)
            if opened.contents.data != payload:
                raise OSError(f"{label} changed during publication")
        for opened in verification_pins:
            opened.revalidate()
        for _path, payload, label, lease, name in prepared:
            matched_output = created_by_entry.get((id(lease), name))
            if matched_output is not None:
                _verify_created_finalize_output(matched_output, payload, label=label)
        _fsync_finalize_output_parents(created)
        completed = True
    except BaseException as exc:
        rollback_errors = _rollback_created_finalize_outputs(created)
        if rollback_errors:
            raise OSError(
                "finalize publication failed and transaction-owned output rollback "
                "was incomplete: " + "; ".join(rollback_errors)
            ) from exc
        raise
    finally:
        verification_close_errors = _close_finalize_verification_pins(verification_pins)
        verification_pins.clear()
        close_errors = _close_created_finalize_outputs(created)
        lock_errors = _release_finalize_output_locks(output_locks)
        parent_close_errors = _close_finalize_parent_leases(parent_leases)
        resource_errors = (
            *verification_close_errors,
            *close_errors,
            *lock_errors,
            *parent_close_errors,
        )
        if resource_errors:
            failure_prefix = (
                "finalize outputs were written" if completed else "finalize publication failed"
            )
            raise OSError(
                f"{failure_prefix} but resource release was incomplete: "
                + "; ".join(resource_errors)
            )


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        return False


def _fsync_finalize_output_parents(created: list[_CreatedFinalizeOutput]) -> None:
    if os.name == "nt":
        return
    fsynced_leases: set[int] = set()
    for output in created:
        lease_key = id(output.lease)
        if lease_key in fsynced_leases:
            continue
        descriptor = output.lease.descriptor
        if descriptor is None:
            raise OSError("finalize output parent descriptor is unavailable")
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != (
            output.lease.device,
            output.lease.inode,
        ):
            raise OSError("finalize output parent identity changed before durability sync")
        os.fsync(descriptor)
        fsynced_leases.add(lease_key)


def _acquire_finalize_output_locks(
    prepared: list[tuple[Path, bytes, str, RootedDirectoryDescriptor, str]],
    *,
    lock_lease: RootedDirectoryDescriptor | None = None,
) -> list[_FinalizeOutputLock]:
    specifications: list[tuple[str, RootedDirectoryDescriptor, str]] = []
    seen_paths: set[str] = set()
    for _path, _payload, _label, lease, name in prepared:
        path_key = os.path.normcase(os.path.abspath(lease.path / name))
        if path_key in seen_paths:
            raise ValueError("finalize output paths must be distinct")
        seen_paths.add(path_key)
        lock_digest = sha256(path_key.encode("utf-8")).hexdigest()
        specifications.append(
            (
                path_key,
                lock_lease or lease,
                f".agent-assure-finalize-{lock_digest}.lock",
            )
        )

    acquired: list[_FinalizeOutputLock] = []
    try:
        for _path_key, lease, name in sorted(specifications, key=lambda item: item[0]):
            descriptor, metadata = lease.open_regular_lock_file(name, mode=0o600)
            output_lock = _FinalizeOutputLock(
                lease=lease,
                name=name,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                descriptor=descriptor,
            )
            acquired.append(output_lock)
            _prepare_finalize_lock_file(output_lock)
            _lock_finalize_descriptor(descriptor)
            output_lock.locked = True
            _verify_finalize_output_lock(output_lock)
    except BaseException as exc:
        release_errors = _release_finalize_output_locks(acquired)
        if release_errors:
            raise OSError(
                "finalize output-lock acquisition failed and cleanup was incomplete: "
                + "; ".join(release_errors)
            ) from exc
        raise
    return acquired


def _prepare_finalize_lock_file(output_lock: _FinalizeOutputLock) -> None:
    metadata = os.fstat(output_lock.descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 1:
        raise ValueError("finalize output lock is not a bounded single-link regular file")
    if metadata.st_size == 0:
        os.lseek(output_lock.descriptor, 0, os.SEEK_SET)
        _write_all(output_lock.descriptor, b"\0")
        os.fsync(output_lock.descriptor)
    os.lseek(output_lock.descriptor, 0, os.SEEK_SET)


def _verify_finalize_output_lock(output_lock: _FinalizeOutputLock) -> None:
    opened = os.fstat(output_lock.descriptor)
    current = output_lock.lease.stat_entry_no_follow(output_lock.name)
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or opened.st_nlink != 1
        or current.st_nlink != 1
        or opened.st_size != 1
        or current.st_size != 1
        or (opened.st_dev, opened.st_ino) != (output_lock.device, output_lock.inode)
        or not os.path.samestat(opened, current)
    ):
        raise OSError("finalize output lock changed while it was being acquired")


def _lock_finalize_descriptor(descriptor: int) -> None:
    acquire_publication_lock(descriptor, label="sensitivity finalize publication")


def _unlock_finalize_descriptor(descriptor: int) -> None:
    release_publication_lock(descriptor)


def _release_finalize_output_locks(
    output_locks: list[_FinalizeOutputLock],
) -> tuple[str, ...]:
    errors: list[str] = []
    for output_lock in reversed(output_locks):
        if output_lock.descriptor < 0:
            continue
        if output_lock.locked:
            try:
                _unlock_finalize_descriptor(output_lock.descriptor)
            except OSError as exc:
                errors.append(f"{output_lock.name}: unlock {exc.__class__.__name__}")
            output_lock.locked = False
        try:
            os.close(output_lock.descriptor)
        except OSError as exc:
            errors.append(f"{output_lock.name}: close {exc.__class__.__name__}")
        else:
            output_lock.descriptor = -1
    return tuple(errors)


def _close_created_finalize_outputs(
    created: list[_CreatedFinalizeOutput],
) -> tuple[str, ...]:
    errors: list[str] = []
    for output in created:
        if output.descriptor < 0:
            continue
        try:
            os.close(output.descriptor)
        except OSError as exc:
            errors.append(f"{output.name}: close {exc.__class__.__name__}")
        else:
            output.descriptor = -1
    return tuple(errors)


def _close_finalize_verification_pins(
    verification_pins: list[PinnedDirectoryFile],
) -> tuple[str, ...]:
    """Close every verification pin without short-circuiting later cleanup."""

    errors: list[str] = []
    for index, opened in reversed(tuple(enumerate(verification_pins))):
        try:
            opened.close()
        except Exception as exc:
            errors.append(f"verification pin {index}: close {exc.__class__.__name__}")
    return tuple(errors)


def _close_finalize_parent_leases(
    parent_leases: dict[str, RootedDirectoryDescriptor],
) -> tuple[str, ...]:
    """Close every parent lease without leaking host paths in diagnostics."""

    errors: list[str] = []
    leases = tuple(parent_leases.values())
    for index, lease in reversed(tuple(enumerate(leases))):
        try:
            lease.close()
        except Exception as exc:
            errors.append(f"parent lease {index}: close {exc.__class__.__name__}")
    return tuple(errors)


def _rollback_created_finalize_outputs(
    created: list[_CreatedFinalizeOutput],
) -> tuple[str, ...]:
    """Remove only final entries created by this failed locked transaction."""

    if not created:
        return ()
    errors = list(_close_created_finalize_outputs(created))
    unlinked_parent_ids: set[int] = set()
    for output in reversed(created):
        try:
            output.lease.unlink_entry_no_follow(
                output.name,
                expected_device=output.device,
                expected_inode=output.inode,
            )
        except (OSError, ValueError) as exc:
            errors.append(f"{output.name}: rollback {exc.__class__.__name__}")
        else:
            unlinked_parent_ids.add(id(output.lease))
    if os.name != "nt":
        for output in created:
            if id(output.lease) not in unlinked_parent_ids:
                continue
            unlinked_parent_ids.remove(id(output.lease))
            descriptor = output.lease.descriptor
            if descriptor is None:
                errors.append(f"{output.name}: rollback parent descriptor unavailable")
                continue
            try:
                os.fsync(descriptor)
            except OSError as exc:
                errors.append(f"{output.name}: rollback parent sync {exc.__class__.__name__}")
    return tuple(errors)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("finalize output write made no progress")
        remaining = remaining[written:]


def _verify_created_finalize_output(
    owned: _CreatedFinalizeOutput,
    payload: bytes,
    *,
    label: str,
) -> None:
    metadata = os.fstat(owned.descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != len(payload)
    ):
        raise OSError(f"{label} changed during publication")
    current = owned.lease.stat_entry_no_follow(owned.name)
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or not os.path.samestat(metadata, current)
    ):
        raise OSError(f"{label} changed during publication")
    os.lseek(owned.descriptor, 0, os.SEEK_SET)
    if _read_exact_descriptor(owned.descriptor, len(payload)) != payload:
        raise OSError(f"{label} changed during publication")


def _read_exact_descriptor(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


__all__ = [
    "bounded_model_json",
    "ensure_finalize_paths",
    "ensure_output_does_not_alias_inputs",
    "is_within",
    "publish_finalize_outputs",
    "reject_inline_environment_for_finalization",
    "same_file",
]
