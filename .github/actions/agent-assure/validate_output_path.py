from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

_WINDOWS_REPARSE_POINT = 0x0400


def _is_link_or_reparse_point(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    )


def _require_unlinked_directory_chain(root: Path, relative_path: Path) -> None:
    current = root
    for component in relative_path.parts:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ValueError("output directory chain cannot be inspected safely") from exc
        if _is_link_or_reparse_point(metadata):
            raise ValueError("output directory has a linked or reparse-point ancestor")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("output directory has a non-directory ancestor")


def validate_output_path(candidate_value: str, allowed_root_values: tuple[str, ...]) -> None:
    if not candidate_value or "\r" in candidate_value or "\n" in candidate_value:
        raise ValueError("output directory must be non-empty and single-line")
    candidate_input = Path(candidate_value)
    if ".." in candidate_input.parts:
        raise ValueError("output directory must not contain parent traversal components")

    lexical_candidate = Path(os.path.abspath(candidate_input))
    if lexical_candidate.parent == lexical_candidate:
        raise ValueError("output directory must not be a filesystem root")
    try:
        resolved_candidate = lexical_candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("output directory cannot be resolved safely") from exc

    matching_roots: list[tuple[Path, Path]] = []
    for root_value in allowed_root_values:
        if not root_value or "\r" in root_value or "\n" in root_value:
            raise ValueError("approved output roots must be non-empty and single-line")
        lexical_root = Path(os.path.abspath(root_value))
        try:
            resolved_root = lexical_root.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError("approved output root must exist and resolve safely") from exc
        if not resolved_root.is_dir():
            raise ValueError("approved output root must be a directory")
        try:
            lexical_relative = lexical_candidate.relative_to(lexical_root)
            resolved_relative = resolved_candidate.relative_to(resolved_root)
        except ValueError:
            continue
        if not lexical_relative.parts or not resolved_relative.parts:
            continue
        matching_roots.append((lexical_root, lexical_relative))

    if not matching_roots:
        raise ValueError("output directory must be strictly below an approved root")
    _require_unlinked_directory_chain(*matching_roots[0])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate a composite-action output directory")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--allowed-root", action="append", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        validate_output_path(arguments.candidate, tuple(arguments.allowed_root))
    except ValueError as exc:
        print(f"agent-assure refuses unsafe output path: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
