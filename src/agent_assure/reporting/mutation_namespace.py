from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

GenerationNamespace = Literal["single", "campaign"]
CAMPAIGN_OPERATOR_FILENAME_INDEX_LIMIT = 1000

_DIRECTORY_SCAN_LIMIT = 4096
_SINGLE_FILENAMES = frozenset(
    {
        "assurance-mutation-result.json",
        "assurance-evidence-descriptor.json",
        "mutated-runset.json",
        "mutation-generation-manifest.json",
    }
)
_CAMPAIGN_GLOBAL_FILENAMES = frozenset(
    {
        "assurance-mutation-catalog.json",
        "assurance-mutation-campaign.json",
        "mutation-campaign-generation-manifest.json",
    }
)
_CAMPAIGN_OPERATOR_PATTERN = re.compile(
    r"^operator-(?P<index>[0-9]{3})-"
    r"(?:mutation-result|evidence-descriptor|mutated-runset)\.json$"
)


def normalized_generation_filename(filename: str) -> str:
    """Normalize names only where the host filesystem is case-insensitive."""
    return os.path.normcase(filename)


def is_single_generation_filename(filename: str) -> bool:
    return normalized_generation_filename(filename) in {
        normalized_generation_filename(item) for item in _SINGLE_FILENAMES
    }


def is_campaign_generation_filename(filename: str) -> bool:
    normalized = normalized_generation_filename(filename)
    if normalized in {normalized_generation_filename(item) for item in _CAMPAIGN_GLOBAL_FILENAMES}:
        return True
    match = _CAMPAIGN_OPERATOR_PATTERN.fullmatch(normalized)
    return match is not None


def assert_generation_namespace_exclusive(
    out_dir: Path,
    *,
    namespace: GenerationNamespace,
) -> None:
    """Reject a directory containing artifacts from the other generation type."""
    foreign = (
        is_campaign_generation_filename if namespace == "single" else is_single_generation_filename
    )
    with os.scandir(out_dir) as entries:
        for index, entry in enumerate(entries):
            if index >= _DIRECTORY_SCAN_LIMIT:
                raise ValueError(
                    "mutation output directory contains too many entries to "
                    "establish an exclusive generation namespace"
                )
            if foreign(entry.name):
                raise ValueError(
                    "mutation output directory mixes single and campaign generation namespaces"
                )
