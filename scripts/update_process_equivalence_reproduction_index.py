from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.artifact_io import write_text_atomic  # noqa: E402
from agent_assure.io_limits import (  # noqa: E402
    load_json_bounded,
    read_file_bounded,
    read_text_bounded,
)
from agent_assure.schema.reproduction_index import (  # noqa: E402
    ProcessEquivalenceReproductionIndex,
    ProcessEquivalenceReproductionIndexSourceArtifact,
    ProcessEquivalenceReproductionIndexSourceClosure,
    ProcessEquivalenceStratum,
)

PUBLIC_REPRODUCTION_INDEX = ROOT / "examples" / "process_equivalence_reproduction_index.json"
PACKAGED_REPRODUCTION_INDEX = (
    ROOT / "src" / "agent_assure" / "examples" / "process_equivalence_reproduction_index.json"
)
SOURCE_ROOTS = {
    ProcessEquivalenceStratum.evidence_insensitivity: ("examples/evidence_sensitivity"),
    ProcessEquivalenceStratum.same_output_different_process: ("examples/prior_auth_synthetic"),
}
MAX_SOURCE_FILES = 4096
MAX_SOURCE_DIRECTORIES = 1024
MAX_SOURCE_TREE_ENTRIES = MAX_SOURCE_FILES + MAX_SOURCE_DIRECTORIES
MAX_SOURCE_DEPTH = 16
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REPRODUCTION_INDEX_BYTES = 4 * 1024 * 1024
MAX_REPRODUCTION_INDEX_CASES = 256
MAX_SOURCE_ARTIFACTS_PER_CASE = 32
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    try:
        rendered = render_updated_reproduction_index(PUBLIC_REPRODUCTION_INDEX)
    except (OSError, TypeError, ValueError) as exc:
        print(f"process-equivalence-reproduction-index: {exc}", file=sys.stderr)
        return 1
    if args.write:
        write_text_atomic(PUBLIC_REPRODUCTION_INDEX, rendered)
        write_text_atomic(PACKAGED_REPRODUCTION_INDEX, rendered)
        print("process-equivalence-reproduction-index: updated")
        return 0
    drift = [
        path
        for path in (PUBLIC_REPRODUCTION_INDEX, PACKAGED_REPRODUCTION_INDEX)
        if read_text_bounded(
            path,
            max_bytes=MAX_REPRODUCTION_INDEX_BYTES,
            label="process-equivalence reproduction index",
        )
        != rendered
    ]
    if drift:
        print(
            "process-equivalence-reproduction-index: stale artifact: "
            + ", ".join(str(path.relative_to(ROOT)) for path in drift),
            file=sys.stderr,
        )
        return 1
    print("process-equivalence-reproduction-index: ok")
    return 0


def render_updated_reproduction_index(
    path: Path,
    *,
    repository_root: Path = ROOT,
) -> str:
    payload = _load_payload(path)
    cases = cast(list[dict[str, Any]], payload["cases"])
    prepared_cases = _prevalidate_case_templates(cases)
    source_closures = {
        source_root: build_source_closure(repository_root, source_root)
        for source_root in sorted({SOURCE_ROOTS[stratum] for _, stratum in prepared_cases})
    }
    for case, stratum in prepared_cases:
        source_root = SOURCE_ROOTS[stratum]
        source_closure = source_closures[source_root]
        case["source_artifacts"] = [
            item.model_dump(mode="json")
            for item in _refresh_source_artifact_anchors(
                case.get("source_artifacts"),
                source_root=source_root,
                source_closure=source_closure,
            )
        ]
        case["source_closure"] = source_closure.model_dump(mode="json")
    payload.pop("reproduction_index_digest", None)
    reproduction_index = ProcessEquivalenceReproductionIndex.build(**payload)
    return json.dumps(reproduction_index.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def _prevalidate_case_templates(
    cases: list[dict[str, Any]],
) -> tuple[tuple[dict[str, Any], ProcessEquivalenceStratum], ...]:
    if not 2 <= len(cases) <= MAX_REPRODUCTION_INDEX_CASES:
        raise ValueError(
            "process-equivalence reproduction-index cases must contain between 2 and "
            f"{MAX_REPRODUCTION_INDEX_CASES} entries"
        )
    prepared: list[tuple[dict[str, Any], ProcessEquivalenceStratum]] = []
    case_ids: list[str] = []
    for index, case in enumerate(cases):
        case_id = case.get("case_id")
        if not isinstance(case_id, str):
            raise TypeError(f"reproduction-index case {index} case_id must be a string")
        case_ids.append(case_id)
        raw_stratum = case.get("stratum")
        if not isinstance(raw_stratum, str):
            raise TypeError(f"reproduction-index case {case_id} stratum must be a string")
        try:
            stratum = ProcessEquivalenceStratum(raw_stratum)
        except ValueError as exc:
            raise ValueError(
                f"reproduction-index case {case_id} has unsupported stratum: {raw_stratum}"
            ) from exc
        source_artifacts = case.get("source_artifacts")
        if not isinstance(source_artifacts, list) or not all(
            isinstance(item, dict) for item in source_artifacts
        ):
            raise TypeError(f"reproduction-index case {case_id} source artifacts must be objects")
        if not 1 <= len(source_artifacts) <= MAX_SOURCE_ARTIFACTS_PER_CASE:
            raise ValueError(
                f"reproduction-index case {case_id} source artifacts must contain between 1 and "
                f"{MAX_SOURCE_ARTIFACTS_PER_CASE} entries"
            )
        prepared.append((case, stratum))
    if case_ids != sorted(case_ids) or len(set(case_ids)) != len(case_ids):
        raise ValueError("reproduction-index cases must use unique canonical case-ID ordering")
    missing_strata = set(ProcessEquivalenceStratum) - {stratum for _, stratum in prepared}
    if missing_strata:
        raise ValueError(
            "reproduction index must contain every required process-equivalence stratum"
        )
    return tuple(prepared)


def _refresh_source_artifact_anchors(
    value: object,
    *,
    source_root: str,
    source_closure: ProcessEquivalenceReproductionIndexSourceClosure,
) -> tuple[ProcessEquivalenceReproductionIndexSourceArtifact, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TypeError("reproduction-index source artifacts must be objects")
    closure_by_path = {f"{source_root}/{item.path}": item.sha256 for item in source_closure.entries}
    anchors: list[ProcessEquivalenceReproductionIndexSourceArtifact] = []
    for item in value:
        path = item.get("path")
        if not isinstance(path, str):
            raise TypeError("reproduction-index source artifact path must be a string")
        sha256 = closure_by_path.get(path)
        if sha256 is None:
            raise ValueError(
                "reproduction-index source artifact anchor is outside its stratum "
                f"source root or absent from its closure: {path}"
            )
        anchors.append(
            ProcessEquivalenceReproductionIndexSourceArtifact(
                path=path,
                sha256=sha256,
            )
        )
    return tuple(sorted(anchors, key=lambda item: item.path))


def build_source_closure(
    repository_root: Path,
    source_root: str,
) -> ProcessEquivalenceReproductionIndexSourceClosure:
    root = repository_root / source_root
    try:
        root_metadata = os.lstat(root)
    except FileNotFoundError as exc:
        raise ValueError(
            f"reproduction-index source root is not a regular directory: {source_root}"
        ) from exc
    if _is_link_or_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(
            f"reproduction-index source root is not a regular directory: {source_root}"
        )
    entries: list[ProcessEquivalenceReproductionIndexSourceArtifact] = []
    for path, metadata in _bounded_source_files(root, source_root=source_root):
        relative = path.relative_to(root)
        entries.append(
            ProcessEquivalenceReproductionIndexSourceArtifact(
                path=relative.as_posix(),
                sha256=_source_file_sha256(path, metadata),
            )
        )
    if not entries:
        raise ValueError(f"reproduction-index source root has no source files: {source_root}")
    return ProcessEquivalenceReproductionIndexSourceClosure.build(
        source_root=source_root,
        entries=tuple(entries),
    )


def _bounded_source_files(
    root: Path,
    *,
    source_root: str,
) -> tuple[tuple[Path, os.stat_result], ...]:
    files: list[tuple[Path, os.stat_result]] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    directory_count = 1
    tree_entry_count = 0
    total_bytes = 0
    while stack:
        directory, depth = stack.pop()
        try:
            children: list[tuple[str, Path]] = []
            with os.scandir(directory) as scanned:
                for child in scanned:
                    tree_entry_count += 1
                    if tree_entry_count > MAX_SOURCE_TREE_ENTRIES:
                        raise ValueError(
                            "reproduction-index source closure exceeds tree entry limit "
                            f"{MAX_SOURCE_TREE_ENTRIES}"
                        )
                    children.append((child.name, Path(child.path)))
        except OSError as exc:
            raise ValueError(
                f"reproduction-index source directory cannot be read: {source_root}"
            ) from exc
        for _name, path in sorted(children, key=lambda item: item[0], reverse=True):
            relative = path.relative_to(root)
            if _is_runtime_cache_path(relative):
                continue
            # DirEntry.stat() reports zero file identities on some supported Windows
            # versions. os.lstat() preserves the identity later compared with fstat().
            metadata = os.lstat(path)
            qualified = f"{source_root}/{relative.as_posix()}"
            if _is_link_or_reparse(metadata):
                raise ValueError(f"reproduction-index source closure refuses links: {qualified}")
            if stat.S_ISDIR(metadata.st_mode):
                child_depth = depth + 1
                if child_depth > MAX_SOURCE_DEPTH:
                    raise ValueError(
                        f"reproduction-index source closure exceeds depth {MAX_SOURCE_DEPTH}: "
                        f"{qualified}"
                    )
                directory_count += 1
                if directory_count > MAX_SOURCE_DIRECTORIES:
                    raise ValueError(
                        "reproduction-index source closure exceeds directory limit "
                        f"{MAX_SOURCE_DIRECTORIES}"
                    )
                stack.append((path, child_depth))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    f"reproduction-index source closure requires regular files: {qualified}"
                )
            if metadata.st_size > MAX_SOURCE_FILE_BYTES:
                raise ValueError(
                    f"reproduction-index source file exceeds {MAX_SOURCE_FILE_BYTES} bytes: "
                    f"{qualified}"
                )
            total_bytes += metadata.st_size
            if total_bytes > MAX_SOURCE_TOTAL_BYTES:
                raise ValueError(
                    "reproduction-index source closure exceeds aggregate byte limit "
                    f"{MAX_SOURCE_TOTAL_BYTES}"
                )
            files.append((path, metadata))
            if len(files) > MAX_SOURCE_FILES:
                raise ValueError(
                    f"reproduction-index source closure exceeds file limit {MAX_SOURCE_FILES}"
                )
    return tuple(sorted(files, key=lambda item: item[0].as_posix()))


def _source_file_sha256(path: Path, expected: os.stat_result) -> str:
    opened = read_file_bounded(
        path,
        max_bytes=MAX_SOURCE_FILE_BYTES,
        label="reproduction-index source file",
    )
    opened_identity = (
        opened.device,
        opened.inode,
        opened.size,
        opened.modified_ns,
    )
    if opened_identity != _file_identity(expected):
        raise ValueError(f"reproduction-index source file changed while opening: {path}")
    return opened.sha256


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    )


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns


def _load_payload(path: Path) -> dict[str, Any]:
    payload = load_json_bounded(
        path,
        max_bytes=MAX_REPRODUCTION_INDEX_BYTES,
        label="process-equivalence reproduction index",
    )
    if not isinstance(payload, dict):
        raise TypeError("process-equivalence reproduction index must be an object")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not all(isinstance(item, dict) for item in cases):
        raise TypeError("process-equivalence reproduction-index cases must be objects")
    return payload


def _is_runtime_cache_path(path: Path) -> bool:
    return "__pycache__" in path.parts or path.suffix == ".pyc"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=("Check or update the closed Process-Equivalence Reproduction Index sources.")
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Rewrite both public and packaged reproduction-index mirrors.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
