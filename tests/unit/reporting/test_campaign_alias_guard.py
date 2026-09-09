from __future__ import annotations

import os
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_assure.reporting import campaign as campaign_reporting


@pytest.mark.parametrize(
    "filename",
    (
        campaign_reporting.MUTATION_CATALOG_FILENAME,
        campaign_reporting.MUTATION_CAMPAIGN_OUTPUT_LOCK_FILENAME,
        "operator-255-mutated-runset.json",
    ),
)
def test_campaign_alias_guard_rejects_lexical_protected_inputs(
    tmp_path: Path,
    filename: str,
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    protected_input = out / filename
    original = b"source-must-remain"
    protected_input.write_bytes(original)

    with pytest.raises(ValueError, match="aliases a protected campaign output"):
        campaign_reporting.ensure_inputs_do_not_alias_mutation_campaign_output(
            (protected_input,),
            out,
        )

    assert protected_input.read_bytes() == original


def test_campaign_alias_guard_rejects_protected_symlink(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    original = b"source-must-remain"
    source.write_bytes(original)
    out = tmp_path / "out"
    out.mkdir()
    alias = out / "operator-255-evidence-descriptor.json"
    try:
        alias.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    with pytest.raises(ValueError, match="aliases a protected campaign output"):
        campaign_reporting.ensure_inputs_do_not_alias_mutation_campaign_output(
            (source,),
            out,
        )

    assert alias.is_symlink()
    assert source.read_bytes() == original


def test_campaign_alias_guard_rejects_resolved_parent_traversal(
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    nested = out / "nested"
    nested.mkdir(parents=True)
    protected_input = out / campaign_reporting.MUTATION_CAMPAIGN_FILENAME
    original = b"source-must-remain"
    protected_input.write_bytes(original)
    resolved_alias = nested / ".." / campaign_reporting.MUTATION_CAMPAIGN_FILENAME

    with pytest.raises(ValueError, match="aliases a protected campaign output"):
        campaign_reporting.ensure_inputs_do_not_alias_mutation_campaign_output(
            (resolved_alias,),
            out,
        )

    assert protected_input.read_bytes() == original


def test_campaign_alias_guard_rejects_protected_hardlink(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    original = b"source-must-remain"
    source.write_bytes(original)
    out = tmp_path / "out"
    out.mkdir()
    alias = out / "operator-255-mutation-result.json"
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(ValueError, match="aliases a protected campaign output"):
        campaign_reporting.ensure_inputs_do_not_alias_mutation_campaign_output(
            (source,),
            out,
        )

    assert os.path.samefile(source, alias)
    assert source.read_bytes() == original


def test_campaign_alias_guard_rejects_case_variant_hardlink_on_case_insensitive_fs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    original = b"source-must-remain"
    source.write_bytes(original)
    out = tmp_path / "out"
    out.mkdir()
    canonical = out / "operator-255-mutation-result.json"
    case_variant = out / canonical.name.upper()
    try:
        os.link(source, case_variant)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    if not canonical.exists():
        pytest.skip("test filesystem is case-sensitive")

    with pytest.raises(ValueError, match="aliases a protected campaign output"):
        campaign_reporting.ensure_inputs_do_not_alias_mutation_campaign_output(
            (source,),
            out,
        )

    assert os.path.samefile(source, canonical)
    assert source.read_bytes() == original


def test_campaign_alias_guard_resolves_output_once_and_compares_only_existing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = (tmp_path / "suite.yaml", tmp_path / "runset.json")
    for source in sources:
        source.write_bytes(b"independent-source")
    out = tmp_path / "out"
    out.mkdir()
    existing_destination = out / "operator-255-mutated-runset.json"
    existing_destination.write_bytes(b"unrelated-prior-output")

    protected_filenames = campaign_reporting._all_protected_output_filenames()
    resolved_calls: list[tuple[Path, bool]] = []
    same_file_calls: list[tuple[Path, Path]] = []
    existing_path_calls: list[tuple[Path, frozenset[str]]] = []
    real_resolved_identity = campaign_reporting._resolved_path_identity
    real_existing_paths = campaign_reporting._existing_protected_output_paths

    def tracked_resolved_identity(path: Path, *, strict: bool) -> str:
        resolved_calls.append((path, strict))
        return real_resolved_identity(path, strict=strict)

    def tracked_same_file(left: Path, right: Path) -> bool:
        same_file_calls.append((left, right))
        return False

    def tracked_existing_paths(
        directory: Path,
        filenames: frozenset[str],
    ) -> tuple[Path, ...]:
        existing_path_calls.append((directory, filenames))
        return real_existing_paths(directory, filenames)

    monkeypatch.setattr(
        campaign_reporting,
        "_resolved_path_identity",
        tracked_resolved_identity,
    )
    monkeypatch.setattr(campaign_reporting, "_same_file", tracked_same_file)
    monkeypatch.setattr(
        campaign_reporting,
        "_existing_protected_output_paths",
        tracked_existing_paths,
    )

    campaign_reporting.ensure_inputs_do_not_alias_mutation_campaign_output(
        sources,
        out,
    )

    expected_protected_count = 4 + (3 * campaign_reporting.CAMPAIGN_OPERATOR_FILENAME_INDEX_LIMIT)
    assert len(protected_filenames) == expected_protected_count
    assert "operator-255-mutated-runset.json" in protected_filenames
    assert resolved_calls == [(source, True) for source in sources]
    assert existing_path_calls == [(out, frozenset(protected_filenames))]
    assert same_file_calls == [(source, existing_destination) for source in sources]


def test_existing_protected_paths_falls_back_to_fixed_lstat_after_scan_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    protected_filenames = frozenset(campaign_reporting._all_protected_output_filenames())
    stale_filename = "operator-255-mutated-runset.json"
    entries = tuple(
        SimpleNamespace(name=f"unrelated-{index:04d}")
        for index in range(campaign_reporting._ALIAS_GUARD_DIRECTORY_SCAN_LIMIT + 1)
    )
    lstat_calls: list[Path] = []

    def fixed_entry_exists(path: Path) -> bool:
        lstat_calls.append(path)
        return path.name == stale_filename

    monkeypatch.setattr(
        vars(campaign_reporting)["os"],
        "scandir",
        lambda _path: nullcontext(entries),
    )
    monkeypatch.setattr(
        vars(campaign_reporting)["_mutation_reporting"],
        "_entry_exists",
        fixed_entry_exists,
    )

    existing = campaign_reporting._existing_protected_output_paths(
        out,
        protected_filenames,
    )

    assert existing == (out / stale_filename,)
    expected_protected_count = 4 + (3 * campaign_reporting.CAMPAIGN_OPERATOR_FILENAME_INDEX_LIMIT)
    assert len(lstat_calls) == expected_protected_count
    assert {path.name for path in lstat_calls} == protected_filenames
