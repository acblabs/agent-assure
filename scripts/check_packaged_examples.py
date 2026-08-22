from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from agent_assure.io_limits import (
    BoundedFileContents,
    open_directory_at,
    open_file_bounded_at,
)
from agent_assure.rooted_io import (
    RootedDirectoryDescriptor,
    portable_relative_path_parts,
)

ROOT = Path(__file__).resolve().parents[1]
TOP_LEVEL_EXAMPLES = ROOT / "examples"
PACKAGED_EXAMPLES = ROOT / "src" / "agent_assure" / "examples"
MAX_MIRRORED_FILES = 4096
MAX_MIRRORED_DIRECTORIES = 4096
MAX_MIRRORED_DEPTH = 32
MAX_MIRRORED_FILE_BYTES = 16 * 1024 * 1024
MAX_MIRRORED_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ROOT_ENTRIES = 128
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400

EXAMPLE_RESOURCE_SETS = (
    "prior_auth_synthetic",
    "expense_approval_minimal",
    "langgraph_expense_assurance",
    "adk_process_assurance",
    "process_measurement_cases",
    "streaming_process_regression",
    "evidence_sensitivity",
)

MIRRORED_RESOURCE_PATHS = (
    Path("README.md"),
    Path("suite.yaml"),
    Path("rag_suite.yaml"),
    Path("fixtures"),
    Path("events"),
    Path("variants"),
    Path("responsive_suite.yaml"),
    Path("evidence_inertial_suite.yaml"),
    Path("evidence_reversed_suite.yaml"),
    Path("knowledge-contract.yaml"),
    Path("corpora"),
)

ROOT_MIRRORED_RESOURCE_PATHS = (Path("process_equivalence_reproduction_index.json"),)
EXTRA_MIRRORED_RESOURCE_PATHS: dict[str, tuple[Path, ...]] = {}

INTENTIONAL_TOP_LEVEL_ONLY = {
    "prior_auth_synthetic": {"app", "cases", "rag", "runner.py"},
    "expense_approval_minimal": {"cases"},
    "langgraph_expense_assurance": {"run_example.py"},
    "adk_process_assurance": {"run_example.py"},
}

INTENTIONAL_PACKAGED_ONLY = {
    "prior_auth_synthetic": {"__init__.py", "app.py", "rag.py", "runner.py"},
    "expense_approval_minimal": {"__init__.py", "runner.py"},
    "langgraph_expense_assurance": {"__init__.py", "runner.py"},
    "adk_process_assurance": {"__init__.py", "runner.py"},
    "process_measurement_cases": {"__init__.py", "runner.py"},
}


@dataclass(frozen=True)
class ExampleDrift:
    example: str
    relative_path: Path
    message: str


def main() -> int:
    drift = compare_packaged_examples(TOP_LEVEL_EXAMPLES, PACKAGED_EXAMPLES)
    if drift:
        for finding in drift:
            print(_format_drift(finding), file=sys.stderr)
        return 1
    print("packaged-examples: ok")
    return 0


def compare_packaged_examples(
    top_level_examples: Path,
    packaged_examples: Path,
) -> list[ExampleDrift]:
    findings = _compare_root_mirrors(top_level_examples, packaged_examples)
    for example in EXAMPLE_RESOURCE_SETS:
        top_root = top_level_examples / example
        packaged_root = packaged_examples / example
        resource_paths = (
            *MIRRORED_RESOURCE_PATHS,
            *EXTRA_MIRRORED_RESOURCE_PATHS.get(example, ()),
        )
        top_files, top_errors = _mirrored_files(top_root, resource_paths=resource_paths)
        packaged_files, packaged_errors = _mirrored_files(
            packaged_root,
            resource_paths=resource_paths,
        )
        findings.extend(
            ExampleDrift(example, path, f"top-level example {message}")
            for path, message in top_errors
        )
        findings.extend(
            ExampleDrift(example, path, f"packaged example {message}")
            for path, message in packaged_errors
        )
        findings.extend(
            _unexpected_root_entries(
                example,
                top_root,
                resource_paths,
                allowed=INTENTIONAL_TOP_LEVEL_ONLY.get(example, set()),
                side="top-level",
            )
        )
        findings.extend(
            _unexpected_root_entries(
                example,
                packaged_root,
                resource_paths,
                allowed=INTENTIONAL_PACKAGED_ONLY.get(example, set()),
                side="packaged",
            )
        )
        relative_paths = sorted(
            set(top_files) | set(packaged_files),
            key=lambda path: path.as_posix(),
        )
        for relative_path in relative_paths:
            if relative_path not in top_files:
                findings.append(
                    ExampleDrift(
                        example=example,
                        relative_path=relative_path,
                        message="packaged example has no top-level counterpart",
                    )
                )
                continue
            if relative_path not in packaged_files:
                findings.append(
                    ExampleDrift(
                        example=example,
                        relative_path=relative_path,
                        message="top-level example is missing from packaged resources",
                    )
                )
                continue
            top_file = top_files[relative_path]
            packaged_file = packaged_files[relative_path]
            if top_file is None or packaged_file is None:
                continue
            if top_file.sha256 != packaged_file.sha256:
                findings.append(
                    ExampleDrift(
                        example=example,
                        relative_path=relative_path,
                        message="top-level and packaged example files differ",
                    )
                )
    return findings


def _compare_root_mirrors(
    top_level_examples: Path,
    packaged_examples: Path,
) -> list[ExampleDrift]:
    findings: list[ExampleDrift] = []
    for relative_path in ROOT_MIRRORED_RESOURCE_PATHS:
        try:
            top_file = _read_rooted_mirror(
                top_level_examples,
                relative_path,
                label="top-level root mirror",
            )
        except FileNotFoundError:
            findings.append(ExampleDrift("<root>", relative_path, "top-level mirror is missing"))
            continue
        except (OSError, ValueError) as exc:
            findings.append(
                ExampleDrift("<root>", relative_path, f"top-level mirror is unsafe: {exc}")
            )
            continue
        try:
            packaged_file = _read_rooted_mirror(
                packaged_examples,
                relative_path,
                label="packaged root mirror",
            )
        except FileNotFoundError:
            findings.append(ExampleDrift("<root>", relative_path, "packaged mirror is missing"))
            continue
        except (OSError, ValueError) as exc:
            findings.append(
                ExampleDrift("<root>", relative_path, f"packaged mirror is unsafe: {exc}")
            )
            continue
        if top_file.sha256 != packaged_file.sha256:
            findings.append(
                ExampleDrift("<root>", relative_path, "top-level and packaged files differ")
            )
    return findings


def _mirrored_files(
    root: Path,
    *,
    resource_paths: tuple[Path, ...],
) -> tuple[dict[Path, BoundedFileContents | None], list[tuple[Path, str]]]:
    files: dict[Path, BoundedFileContents | None] = {}
    errors: list[tuple[Path, str]] = []
    total_bytes = 0
    directory_count = 0
    stopped = False
    seen_directories: set[Path] = set()

    def collect_file(
        relative: Path,
        metadata: os.stat_result,
        *,
        anchor: RootedDirectoryDescriptor,
    ) -> None:
        nonlocal stopped, total_bytes
        if relative in files or stopped:
            return
        if len(files) >= MAX_MIRRORED_FILES:
            errors.append((relative, f"exceeds {MAX_MIRRORED_FILES} mirrored files"))
            stopped = True
            return
        try:
            with open_file_bounded_at(
                root,
                relative,
                max_bytes=MAX_MIRRORED_FILE_BYTES,
                label="mirrored example file",
            ) as opened:
                _require_same_root(
                    anchor,
                    root_device=opened.root_device,
                    root_inode=opened.root_inode,
                    relative=relative,
                )
                contents = opened.contents
        except (OSError, ValueError) as exc:
            files[relative] = None
            errors.append((relative, f"cannot be read safely: {exc}"))
            return
        if not _file_snapshot_matches_inventory(contents, metadata):
            files[relative] = None
            errors.append((relative, "changed between inventory and bounded read"))
            return
        if total_bytes + contents.size > MAX_MIRRORED_TOTAL_BYTES:
            files[relative] = None
            errors.append((relative, f"exceeds {MAX_MIRRORED_TOTAL_BYTES} mirrored bytes"))
            stopped = True
            return
        files[relative] = contents
        total_bytes += contents.size

    def collect_entry(
        relative: Path,
        metadata: os.stat_result,
        *,
        depth: int,
        anchor: RootedDirectoryDescriptor,
    ) -> None:
        nonlocal directory_count, stopped
        if stopped:
            return
        try:
            portable_relative_path_parts(relative)
        except ValueError as exc:
            errors.append((relative, f"contains an unsafe portable path: {exc}"))
            return
        if _is_link_or_reparse(metadata):
            errors.append((relative, "contains a symbolic link or reparse point"))
            return
        if stat.S_ISREG(metadata.st_mode):
            collect_file(relative, metadata, anchor=anchor)
            return
        if not stat.S_ISDIR(metadata.st_mode):
            errors.append((relative, "contains a non-regular filesystem entry"))
            return
        if relative in seen_directories:
            return
        if depth > MAX_MIRRORED_DEPTH:
            errors.append((relative, f"exceeds mirrored depth {MAX_MIRRORED_DEPTH}"))
            return
        directory_count += 1
        if directory_count > MAX_MIRRORED_DIRECTORIES:
            errors.append((relative, f"exceeds {MAX_MIRRORED_DIRECTORIES} mirrored directories"))
            stopped = True
            return
        seen_directories.add(relative)
        try:
            with open_directory_at(
                root,
                relative,
                label="mirrored example directory",
            ) as directory:
                _require_same_root(
                    anchor,
                    root_device=directory.root_device,
                    root_inode=directory.root_inode,
                    relative=relative,
                )
                if not _directory_lease_matches_inventory(directory, metadata):
                    raise ValueError("directory changed between inventory and descriptor lease")
                children = _bounded_inventory_entries(
                    directory,
                    maximum=MAX_MIRRORED_FILES + MAX_MIRRORED_DIRECTORIES,
                )
                for child in children:
                    collect_entry(
                        relative / child.name,
                        child.metadata,
                        depth=depth + 1,
                        anchor=anchor,
                    )
        except (OSError, ValueError) as exc:
            errors.append((relative, f"cannot be inventoried safely: {exc}"))
            return

    def collect_resource(
        resource_path: Path,
        *,
        anchor: RootedDirectoryDescriptor,
    ) -> None:
        try:
            parts = portable_relative_path_parts(resource_path)
        except ValueError as exc:
            errors.append((resource_path, f"resource path is unsafe: {exc}"))
            return
        relative = Path(*parts)
        parent = Path(*parts[:-1]) if len(parts) > 1 else Path(".")
        try:
            with open_directory_at(
                root,
                parent,
                label="mirrored resource parent",
            ) as directory:
                _require_same_root(
                    anchor,
                    root_device=directory.root_device,
                    root_inode=directory.root_inode,
                    relative=parent,
                )
                entries = _bounded_inventory_entries(
                    directory,
                    maximum=MAX_MIRRORED_FILES + MAX_MIRRORED_DIRECTORIES,
                )
                entry = next((item for item in entries if item.name == parts[-1]), None)
                if entry is None:
                    return
                collect_entry(
                    relative,
                    entry.metadata,
                    depth=0,
                    anchor=anchor,
                )
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            errors.append((relative, f"cannot be inventoried safely: {exc}"))

    try:
        with open_directory_at(root, ".", label="mirrored example root") as anchor:
            for resource_path in resource_paths:
                collect_resource(resource_path, anchor=anchor)
    except FileNotFoundError:
        return files, [(Path("."), "root is missing")]
    except (OSError, ValueError) as exc:
        return files, [(Path("."), f"root cannot be leased safely: {exc}")]
    return files, errors


def _unexpected_root_entries(
    example: str,
    root: Path,
    resource_paths: tuple[Path, ...],
    *,
    allowed: set[str],
    side: str,
) -> list[ExampleDrift]:
    mirrored_roots = {path.parts[0] for path in resource_paths}
    findings: list[ExampleDrift] = []
    try:
        root_context = open_directory_at(root, ".", label=f"{side} example root")
    except FileNotFoundError:
        return findings
    except (OSError, ValueError) as exc:
        return [
            ExampleDrift(
                example,
                Path("."),
                f"{side} root cannot be leased safely: {exc}",
            )
        ]
    with root_context as anchor:
        try:
            root_entries = _bounded_inventory_entries(anchor, maximum=MAX_ROOT_ENTRIES)
        except (OSError, ValueError) as exc:
            return [
                ExampleDrift(
                    example,
                    Path("."),
                    f"{side} root cannot be inventoried safely: {exc}",
                )
            ]
        for entry in root_entries:
            if entry.name == "__pycache__" or Path(entry.name).suffix == ".pyc":
                continue
            relative = Path(entry.name)
            metadata = entry.metadata
            if _is_link_or_reparse(metadata) or not (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
            ):
                findings.append(
                    ExampleDrift(
                        example,
                        relative,
                        f"{side} root entry is linked, reparse-backed, or non-regular",
                    )
                )
                continue
            try:
                portable_relative_path_parts(relative)
                if stat.S_ISREG(metadata.st_mode):
                    with open_file_bounded_at(
                        root,
                        relative,
                        max_bytes=MAX_MIRRORED_FILE_BYTES,
                        label=f"{side} example root file",
                    ) as opened:
                        _require_same_root(
                            anchor,
                            root_device=opened.root_device,
                            root_inode=opened.root_inode,
                            relative=relative,
                        )
                        if not _file_snapshot_matches_inventory(
                            opened.contents,
                            metadata,
                        ):
                            raise ValueError("file changed between inventory and bounded read")
                else:
                    with open_directory_at(
                        root,
                        relative,
                        label=f"{side} example root directory",
                    ) as opened_directory:
                        _require_same_root(
                            anchor,
                            root_device=opened_directory.root_device,
                            root_inode=opened_directory.root_inode,
                            relative=relative,
                        )
                        if not _directory_lease_matches_inventory(
                            opened_directory,
                            metadata,
                        ):
                            raise ValueError(
                                "directory changed between inventory and descriptor lease"
                            )
            except (OSError, ValueError) as exc:
                findings.append(
                    ExampleDrift(
                        example,
                        relative,
                        f"{side} root entry is unreadable: {exc}",
                    )
                )
                continue
            if entry.name not in mirrored_roots and entry.name not in allowed:
                findings.append(ExampleDrift(example, relative, f"unexpected {side} root entry"))
    return findings


@dataclass(frozen=True)
class _InventoryEntry:
    name: str
    metadata: os.stat_result


def _read_rooted_mirror(
    root: Path,
    relative_path: Path,
    *,
    label: str,
) -> BoundedFileContents:
    with open_directory_at(root, ".", label=f"{label} root") as anchor:
        with open_file_bounded_at(
            root,
            relative_path,
            max_bytes=MAX_MIRRORED_FILE_BYTES,
            label=label,
        ) as opened:
            _require_same_root(
                anchor,
                root_device=opened.root_device,
                root_inode=opened.root_inode,
                relative=relative_path,
            )
            return opened.contents


def _bounded_inventory_entries(
    directory: RootedDirectoryDescriptor,
    *,
    maximum: int,
) -> tuple[_InventoryEntry, ...]:
    entries: list[_InventoryEntry] = []
    scan_target: int | Path = (
        directory.descriptor if directory.descriptor is not None else directory.path
    )
    with os.scandir(scan_target) as iterator:
        for entry in iterator:
            if len(entries) >= maximum:
                raise ValueError(f"directory exceeds {maximum} entries: {directory.path}")
            entries.append(
                _InventoryEntry(
                    name=entry.name,
                    metadata=entry.stat(follow_symlinks=False),
                )
            )
    return tuple(sorted(entries, key=lambda entry: entry.name))


def _require_same_root(
    anchor: RootedDirectoryDescriptor,
    *,
    root_device: int,
    root_inode: int,
    relative: Path,
) -> None:
    if (root_device, root_inode) != (anchor.root_device, anchor.root_inode):
        raise ValueError(f"trusted root changed while reading: {relative}")


def _file_snapshot_matches_inventory(
    contents: BoundedFileContents,
    metadata: os.stat_result,
) -> bool:
    if (
        contents.size,
        contents.modified_ns,
        contents.changed_ns,
    ) != (
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ):
        return False
    # CPython's Windows scandir cache can expose zero st_dev/st_ino even though
    # a subsequent stat and the rooted handle have stable file identities. Keep
    # the stronger identity comparison wherever the inventory supplied one.
    if metadata.st_dev or metadata.st_ino:
        return (contents.device, contents.inode) == (
            metadata.st_dev,
            metadata.st_ino,
        )
    return True


def _directory_lease_matches_inventory(
    directory: RootedDirectoryDescriptor,
    metadata: os.stat_result,
) -> bool:
    if metadata.st_dev or metadata.st_ino:
        return (directory.device, directory.inode) == (
            metadata.st_dev,
            metadata.st_ino,
        )
    # On Windows the scandir cache can omit identity fields, and directory
    # timestamps can update lazily. The rooted lease itself is authoritative:
    # it rejects reparse points, pins every component, and revalidates the
    # final handle identity before returning.
    return True


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    )


def _format_drift(drift: ExampleDrift) -> str:
    return f"packaged-examples: {drift.example}/{drift.relative_path.as_posix()}: {drift.message}"


if __name__ == "__main__":
    raise SystemExit(main())
