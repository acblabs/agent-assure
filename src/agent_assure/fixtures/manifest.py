from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from agent_assure.artifact_io import write_text_atomic
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.resolver import FixtureResolver
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    read_bytes_bounded_at,
)
from agent_assure.onboarding.path_safety import (
    metadata_is_regular_directory,
    metadata_is_regular_file,
    metadata_is_reparse,
)
from agent_assure.schema.suite import CompiledSuite, FixtureManifest, FixtureManifestEntry
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
)

REQUIRED_FIXTURE_SUBDIRS = ("requests", "model_outputs", "tool_outputs")


MAX_FIXTURE_MANIFEST_ENTRIES = 8_192
MAX_FIXTURE_MANIFEST_DIRECTORIES = 2_048
MAX_FIXTURE_MANIFEST_DEPTH = 16
MAX_FIXTURE_MANIFEST_AGGREGATE_BYTES = 64 * 1024 * 1024


def build_fixture_manifest(compiled: CompiledSuite, suite_root: Path) -> FixtureManifest:
    resolver = FixtureResolver(suite_root)
    validate_fixture_layout(compiled, resolver)
    entries: list[FixtureManifestEntry] = []
    verified_bytes = 0
    for fixture_root in sorted(compiled.defaults.fixture_roots):
        root_path = resolver.resolve(fixture_root)
        fixture_paths = _iter_fixture_files(root_path)
        if len(entries) + len(fixture_paths) > MAX_FIXTURE_MANIFEST_ENTRIES:
            raise ValueError("fixture manifest exceeds the entry limit")
        for path in fixture_paths:
            entry = _entry_for_path(path, resolver)
            verified_bytes += entry.size_bytes
            if verified_bytes > MAX_FIXTURE_MANIFEST_AGGREGATE_BYTES:
                raise ValueError("fixture manifest exceeds the aggregate byte limit")
            entries.append(entry)
    return FixtureManifest(
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        fixture_roots=tuple(sorted(compiled.defaults.fixture_roots)),
        entries=tuple(sorted(entries, key=lambda entry: entry.path)),
    )


def load_fixture_manifest(path: Path) -> FixtureManifest:
    payload = load_validated_artifact_payload(
        path,
        "fixture-manifest",
        label="fixture manifest JSON",
    )
    return project_validated_artifact_payload(
        payload,
        FixtureManifest,
        kind="fixture-manifest",
    )


def write_fixture_manifest(manifest: FixtureManifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(
        path,
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
    )


def fixture_manifest_digest(manifest: FixtureManifest) -> str:
    return sha256_hexdigest(manifest.model_dump(mode="json"))


def verify_fixture_manifest(
    manifest: FixtureManifest,
    compiled: CompiledSuite,
    suite_root: Path,
) -> None:
    current = build_fixture_manifest(compiled, suite_root)
    if current.model_dump(mode="json") != manifest.model_dump(mode="json"):
        raise ValueError("fixture manifest does not match current fixture files")


def validate_fixture_layout(compiled: CompiledSuite, resolver: FixtureResolver) -> None:
    seen_roots: set[str] = set()
    for fixture_root in compiled.defaults.fixture_roots:
        if fixture_root in seen_roots:
            raise ValueError(f"duplicate fixture root declared: {fixture_root}")
        seen_roots.add(fixture_root)
        root_path = resolver.resolve(fixture_root)
        if not root_path.exists():
            raise FileNotFoundError(f"declared fixture root does not exist: {fixture_root}")
        if not root_path.is_dir():
            raise NotADirectoryError(f"declared fixture root is not a directory: {fixture_root}")
        for subdir in REQUIRED_FIXTURE_SUBDIRS:
            subdir_path = resolver.resolve(f"{fixture_root}/{subdir}")
            if not subdir_path.exists():
                raise FileNotFoundError(
                    f"declared fixture root missing required subdirectory: {fixture_root}/{subdir}"
                )
            if not subdir_path.is_dir():
                raise NotADirectoryError(
                    f"declared fixture subpath is not a directory: {fixture_root}/{subdir}"
                )
    for case in compiled.cases:
        _resolve_case_fixture_root(compiled, resolver, case.fixture_id or case.case_id)


def resolve_case_fixture_paths(
    compiled: CompiledSuite,
    resolver: FixtureResolver,
    fixture_id: str,
) -> dict[str, Path]:
    root = _resolve_case_fixture_root(compiled, resolver, fixture_id)
    return {
        subdir: resolver.resolve(f"{root}/{subdir}/{fixture_id}.json")
        for subdir in REQUIRED_FIXTURE_SUBDIRS
    }


def _resolve_case_fixture_root(
    compiled: CompiledSuite,
    resolver: FixtureResolver,
    fixture_id: str,
) -> str:
    matches: list[str] = []
    incomplete: list[str] = []
    for fixture_root in compiled.defaults.fixture_roots:
        paths = [
            resolver.resolve(f"{fixture_root}/{subdir}/{fixture_id}.json")
            for subdir in REQUIRED_FIXTURE_SUBDIRS
        ]
        existing = [path.exists() for path in paths]
        if all(existing):
            matches.append(fixture_root)
        elif any(existing):
            incomplete.append(fixture_root)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        roots = ", ".join(matches)
        raise ValueError(f"fixture_id {fixture_id!r} is ambiguous across fixture roots: {roots}")
    details = f"; incomplete roots: {', '.join(incomplete)}" if incomplete else ""
    raise FileNotFoundError(
        f"fixture_id {fixture_id!r} not found in declared fixture roots{details}"
    )


def _iter_fixture_files(root_path: Path) -> tuple[Path, ...]:
    paths: list[Path] = []
    pending = [(root_path, 0)]
    entry_count = 0
    directory_count = 1
    aggregate_file_bytes = 0
    while pending:
        directory, depth = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > MAX_FIXTURE_MANIFEST_ENTRIES:
                    raise ValueError("fixture manifest exceeds the entry limit")
                path = Path(entry.path)
                metadata = entry.stat(follow_symlinks=False)
                if metadata_is_reparse(metadata):
                    raise ValueError("fixture manifest refuses symlinked path or reparse point")
                if metadata_is_regular_directory(metadata):
                    if depth >= MAX_FIXTURE_MANIFEST_DEPTH:
                        raise ValueError("fixture manifest exceeds the directory depth limit")
                    directory_count += 1
                    if directory_count > MAX_FIXTURE_MANIFEST_DIRECTORIES:
                        raise ValueError("fixture manifest exceeds the directory limit")
                    pending.append((path, depth + 1))
                elif metadata_is_regular_file(metadata):
                    aggregate_file_bytes += metadata.st_size
                    if aggregate_file_bytes > MAX_FIXTURE_MANIFEST_AGGREGATE_BYTES:
                        raise ValueError("fixture manifest exceeds the aggregate byte limit")
                    paths.append(path)
                else:
                    raise ValueError("fixture manifest contains a non-regular entry")
    return tuple(sorted(paths, key=_path_key))


def _entry_for_path(path: Path, resolver: FixtureResolver) -> FixtureManifestEntry:
    manifest_path = resolver.manifest_path(path)
    data = read_bytes_bounded_at(
        resolver.resolved_root,
        manifest_path,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="fixture file",
    )
    return FixtureManifestEntry(
        path=manifest_path,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def _path_key(path: Path) -> str:
    return path.as_posix()
