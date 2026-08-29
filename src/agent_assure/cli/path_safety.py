from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path


def ensure_inputs_do_not_alias_outputs(
    inputs: Iterable[Path | None],
    outputs: Iterable[Path | None],
    *,
    owner: str,
) -> None:
    """Fail before writes when an owned output aliases any declared input.

    Resolved path equality catches direct and symlink aliases; ``samefile``
    additionally catches existing hard links. Output/output aliases are also
    rejected so multi-artifact commands cannot overwrite an earlier result.
    """
    input_paths = tuple(path for path in inputs if path is not None)
    output_paths = tuple(path for path in outputs if path is not None)
    try:
        # Typer normally guarantees declared inputs exist, while direct library
        # calls may intentionally exercise parser errors with a later unused
        # path. Non-strict resolution still normalizes direct/symlink aliases;
        # samefile adds hard-link identity whenever both entries exist.
        input_identities = tuple(path.resolve(strict=False) for path in input_paths)
        output_identities = tuple(path.resolve(strict=False) for path in output_paths)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{owner} input or output path cannot be safely resolved") from exc

    for index, (output, identity) in enumerate(zip(output_paths, output_identities, strict=True)):
        for prior, prior_identity in zip(
            output_paths[:index],
            output_identities[:index],
            strict=True,
        ):
            if identity == prior_identity or _same_file(output, prior):
                raise ValueError(f"{owner} owned output paths alias each other")

    for source, source_identity in zip(input_paths, input_identities, strict=True):
        for destination, destination_identity in zip(
            output_paths,
            output_identities,
            strict=True,
        ):
            if source_identity == destination_identity or _same_file(source, destination):
                raise ValueError(f"{owner} input aliases an owned output path")


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (FileNotFoundError, OSError):
        return False
