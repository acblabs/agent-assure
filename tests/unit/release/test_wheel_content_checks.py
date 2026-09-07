from __future__ import annotations

import base64
import hashlib
import io
import stat
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

import scripts.check_wheel_contents as wheel_content_checks
from scripts.check_wheel_contents import (
    _metadata_identity,
    _portable_archive_member_error,
    inspect_sdist,
    inspect_wheel,
    required_archive_paths,
    required_sdist_paths,
    validate_distribution_directory,
    validate_distribution_identity,
    validate_distribution_payload_equivalence,
    validate_wheel_archive_equivalence,
)
from scripts.schema_versions import frozen_schema_versions, schema_packaging_failures
from scripts.sync_schema_force_includes import replace_force_include_block

ROOT = Path(__file__).resolve().parents[3]


def test_required_archive_paths_include_every_v030_schema(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    (schema_root / "v0.3.0").mkdir(parents=True)
    (schema_root / "v0.3.0" / "agent-run-record.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (schema_root / "v0.3.0" / "evidence-packet.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    required = required_archive_paths(
        schema_root=schema_root,
        schema_versions=("v0.3.0",),
    )

    assert "agent_assure/schema_resources/v0.3.0/agent-run-record.schema.json" in required
    assert "agent_assure/schema_resources/v0.3.0/evidence-packet.schema.json" in required
    assert "agent_assure/mutation/introduction_snapshots.json" in required
    assert "agent_assure/mutation/campaign.py" in required
    assert "agent_assure/reporting/campaign.py" in required
    assert "agent_assure/schema/campaign.py" in required
    assert (
        "agent_assure/examples/prior_auth_synthetic/fixtures/rag/counterfactual_query_families.json"
    ) in required
    assert "agent_assure/mappings/nist_ai_rmf.yaml" in required
    assert "agent_assure/mappings/mitre_atlas_2026_06.yaml" in required
    assert "agent_assure/examples/langgraph_expense_assurance/runner.py" in required
    assert "agent_assure/examples/langgraph_expense_assurance/suite.yaml" in required
    assert "agent_assure/examples/adk_process_assurance/runner.py" in required
    assert "agent_assure/examples/adk_process_assurance/suite.yaml" in required
    assert "agent_assure/examples/process_measurement_cases/runner.py" in required
    assert "agent_assure/examples/process_measurement_cases/suite.yaml" in required
    assert (
        "agent_assure/examples/process_measurement_cases/fixtures/shared/model_outputs/"
        "same-output-provider-boundary.json"
    ) in required
    assert "agent_assure/examples/streaming_process_regression/suite.yaml" in required
    assert (
        "agent_assure/examples/streaming_process_regression/events/candidate_review_bypassed.jsonl"
    ) in required
    assert "agent_assure/cli/rag_cmd.py" in required
    assert "agent_assure/cli/study_cmd.py" in required
    assert "agent_assure/rag/sensitivity.py" in required
    assert "agent_assure/reporting/study.py" in required
    assert "agent_assure/reporting/sensitivity.py" in required
    assert "agent_assure/schema/benchmark.py" in required
    assert "agent_assure/schema/pilot.py" in required
    assert "agent_assure/schema/sensitivity.py" in required
    assert "agent_assure/schema/study.py" in required
    assert "agent_assure/statistics/binomial_intervals.py" in required
    assert "agent_assure/study/analysis.py" in required
    assert "agent_assure/examples/evidence_sensitivity/responsive_suite.yaml" in required
    assert ("agent_assure/examples/evidence_sensitivity/evidence_inertial_suite.yaml") in required
    assert "agent_assure/examples/evidence_sensitivity/evidence_reversed_suite.yaml" in required
    assert (
        "agent_assure/examples/evidence_sensitivity/corpora/policy_b/corpus-manifest.json"
    ) in required
    assert (
        "agent_assure/examples/evidence_sensitivity/fixtures/evidence_inertial/"
        "model_outputs/synthetic-benefit-eligibility.json"
    ) in required
    for fixture_kind in ("requests", "model_outputs", "tool_outputs"):
        assert (
            "agent_assure/examples/evidence_sensitivity/fixtures/evidence_reversed/"
            f"{fixture_kind}/synthetic-benefit-eligibility.json"
        ) in required
    assert "agent_assure/examples/process_equivalence_reproduction_index.json" in required
    assert (
        "agent_assure/examples/process_equivalence_benchmark_v0_2/benchmark.json"
        in required
    )
    assert (
        "agent_assure/examples/process_equivalence_benchmark_v0_2/"
        "inputs/synthetic-benefit-eligibility-008.json"
        in required
    )


def test_required_archive_paths_include_v061_campaign_contracts(
    tmp_path: Path,
) -> None:
    schema_root = tmp_path / "schemas"
    version_root = schema_root / "v0.6.1"
    version_root.mkdir(parents=True)
    for name in (
        "assurance-mutation-campaign.schema.json",
        "assurance-mutation-catalog.schema.json",
        "run-set.schema.json",
    ):
        (version_root / name).write_text("{}\n", encoding="utf-8")

    required = required_archive_paths(
        schema_root=schema_root,
        schema_versions=("v0.6.1",),
    )

    assert (
        "agent_assure/schema_resources/v0.6.1/assurance-mutation-campaign.schema.json"
    ) in required
    assert (
        "agent_assure/schema_resources/v0.6.1/assurance-mutation-catalog.schema.json"
    ) in required
    assert "agent_assure/schema_resources/v0.6.1/run-set.schema.json" in required


def test_frozen_schema_versions_are_discovered_from_schema_root(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    for version in ("v0.3.1", "v0.1.0", "unreleased", "v0.2.0"):
        (schema_root / version).mkdir(parents=True)
    (schema_root / "v0.1.0" / "compiled-suite.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (schema_root / "v0.2.0" / "compiled-suite.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (schema_root / "v0.3.1" / "compiled-suite.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (schema_root / "unreleased" / "compiled-suite.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    assert frozen_schema_versions(schema_root) == ("v0.1.0", "v0.2.0", "v0.3.1")


def test_schema_packaging_failures_report_missing_and_stale_force_includes(
    tmp_path: Path,
) -> None:
    schema_root = tmp_path / "schemas"
    for version in ("v0.1.0", "v0.2.0"):
        (schema_root / version).mkdir(parents=True)
        (schema_root / version / "compiled-suite.schema.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.hatch.build.targets.wheel.force-include]
"schemas/v0.1.0" = "agent_assure/schema_resources/v0.1.0"
"schemas/v0.0.9" = "agent_assure/schema_resources/v0.0.9"
""".lstrip(),
        encoding="utf-8",
    )

    failures = schema_packaging_failures(schema_root=schema_root, pyproject=pyproject)

    assert any("schemas/v0.2.0" in failure for failure in failures)
    assert any("schemas/v0.0.9" in failure for failure in failures)


def test_schema_packaging_failures_report_new_frozen_schema_without_force_include(
    tmp_path: Path,
) -> None:
    schema_root = tmp_path / "schemas"
    for version in ("v0.3.1", "v9.9.9"):
        (schema_root / version).mkdir(parents=True)
        (schema_root / version / "compiled-suite.schema.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.hatch.build.targets.wheel.force-include]
"schemas/v0.3.1" = "agent_assure/schema_resources/v0.3.1"
""".lstrip(),
        encoding="utf-8",
    )

    failures = schema_packaging_failures(schema_root=schema_root, pyproject=pyproject)

    assert len(failures) == 1
    assert "missing schema force-include" in failures[0]
    assert "'schemas/v9.9.9' = 'agent_assure/schema_resources/v9.9.9'" in failures[0]


def test_schema_force_include_sync_replaces_static_block(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    for version in ("v0.1.0", "v0.2.0"):
        (schema_root / version).mkdir(parents=True)
        (schema_root / version / "compiled-suite.schema.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
    original = """
[project]
name = "agent-assure"

[tool.hatch.build.targets.wheel.force-include]
"schemas/v0.1.0" = "agent_assure/schema_resources/v0.1.0"

[tool.hatch.build.targets.sdist]
include = ["src/agent_assure/**/*"]
""".lstrip()

    updated = replace_force_include_block(original, schema_root=schema_root)

    assert '"mappings" = "agent_assure/mappings"' in updated
    assert '"schemas/v0.2.0" = "agent_assure/schema_resources/v0.2.0"' in updated
    assert "[tool.hatch.build.targets.sdist]" in updated


def test_make_schemas_syncs_schema_force_includes() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    schemas_target = makefile[
        makefile.index("schemas:") : makefile.index("\nschema-force-includes:")
    ]

    assert "scripts/run_source_cli.py schema export" in schemas_target
    assert "scripts/sync_schema_force_includes.py" in schemas_target


def test_inspect_wheel_reports_missing_frozen_schema_file(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.3.0-py3-none-any.whl"
    required = set(required_archive_paths())
    missing_schema = "agent_assure/schema_resources/v0.3.0/evidence-packet.schema.json"
    required.remove(missing_schema)
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in sorted(required):
            if path.endswith("/"):
                archive.writestr(f"{path}.keep", "")
            else:
                archive.writestr(path, "{}\n")

    missing, forbidden = inspect_wheel(wheel)

    assert missing_schema in missing
    assert forbidden == []


def test_inspect_wheel_reports_missing_reversed_control_resources(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    missing_reversed = {
        "agent_assure/examples/evidence_sensitivity/evidence_reversed_suite.yaml",
        *(
            "agent_assure/examples/evidence_sensitivity/fixtures/evidence_reversed/"
            f"{fixture_kind}/synthetic-benefit-eligibility.json"
            for fixture_kind in ("requests", "model_outputs", "tool_outputs")
        ),
    }
    required = set(required_archive_paths()) - missing_reversed
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in sorted(required):
            if path.endswith("/"):
                archive.writestr(f"{path}.keep", "")
            else:
                archive.writestr(path, "{}\n")

    missing, forbidden = inspect_wheel(wheel)

    assert set(missing) == missing_reversed
    assert forbidden == []


def test_inspect_sdist_reports_unreleased_schema_files(tmp_path: Path) -> None:
    sdist = tmp_path / "agent_assure-0.3.1.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        _write_tar_member(
            archive,
            "agent_assure-0.3.1/schemas/v0.3.1/usage-summary.schema.json",
            "{}\n",
        )
        _write_tar_member(
            archive,
            "agent_assure-0.3.1/schemas/unreleased/usage-summary.schema.json",
            "{}\n",
        )

    missing, forbidden = inspect_sdist(sdist)

    assert "agent_assure-0.3.1/schemas/unreleased/usage-summary.schema.json" in forbidden

    assert "pyproject.toml" in missing


def test_inspect_wheel_rejects_unsafe_paths_links_and_duplicates(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    link = zipfile.ZipInfo("agent_assure/examples/host-link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("../wheel-escape.py", "")
        archive.writestr("/absolute-wheel.py", "")
        archive.writestr("agent_assure\\windows-escape.py", "")
        archive.writestr(link, "../../outside")
        archive.writestr("agent_assure/__init__.py", "")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("agent_assure/__init__.py", "")

    _missing, forbidden = inspect_wheel(wheel)

    rendered = "\n".join(forbidden)
    assert "parent segment" in rendered
    assert "absolute archive member path" in rendered
    assert "backslash" in (_portable_archive_member_error("agent_assure\\escape.py") or "")
    assert "not a regular file or directory" in rendered
    assert "duplicate or portable-path collision" in rendered


def test_inspect_sdist_rejects_unsafe_paths_links_and_duplicates(tmp_path: Path) -> None:
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        _write_tar_member(archive, "agent_assure-0.6.4/../../escape.py", "")
        _write_tar_member(archive, "/absolute.py", "")
        _write_tar_member(archive, "agent_assure-0.6.4/duplicate.py", "")
        _write_tar_member(archive, "agent_assure-0.6.4/duplicate.py", "")
        link = tarfile.TarInfo("agent_assure-0.6.4/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    _missing, forbidden = inspect_sdist(sdist)

    rendered = "\n".join(forbidden)
    assert "parent segment" in rendered
    assert "absolute archive member path" in rendered
    assert "duplicate or portable-path collision" in rendered
    assert "not a regular file or directory" in rendered


@pytest.mark.parametrize("character", ("<", ">", '"', "|", "?", "*"))
def test_portable_archive_paths_reject_windows_forbidden_characters(
    character: str,
) -> None:
    issue = _portable_archive_member_error(f"agent_assure/bad{character}name.py")

    assert issue is not None
    assert "Windows-forbidden character" in issue


def test_inspect_wheel_rejects_file_descendant_conflicts(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agent_assure/conflict", "file")
        archive.writestr("agent_assure/conflict/child.py", "child")

    _missing, forbidden = inspect_wheel(wheel)

    assert any("descends from regular file agent_assure/conflict" in item for item in forbidden)


def test_inspect_sdist_rejects_file_descendant_conflicts(tmp_path: Path) -> None:
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        _write_tar_member(archive, "agent_assure-0.6.4/conflict", "file")
        _write_tar_member(archive, "agent_assure-0.6.4/conflict/child.py", "child")

    _missing, forbidden = inspect_sdist(sdist)

    assert any(
        "descends from regular file agent_assure-0.6.4/conflict" in item for item in forbidden
    )


def test_wheel_member_count_is_bounded_before_zipfile_parses_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    wheel.write_bytes(
        struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            1,
            1,
            0,
            0,
            0,
        )
    )
    monkeypatch.setattr(wheel_content_checks, "MAX_ARCHIVE_MEMBERS", 0)

    with pytest.raises(ValueError, match="advertises 1 members"):
        inspect_wheel(wheel)


def test_sdist_extended_headers_are_bounded_before_tarfile_consumes_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        data = b"x"
        member = tarfile.TarInfo("agent_assure-0.6.4/member.txt")
        member.size = len(data)
        member.pax_headers = {"comment": "x" * 4096}
        archive.addfile(member, io.BytesIO(data))
    monkeypatch.setattr(wheel_content_checks, "MAX_TAR_EXTENDED_HEADER_BYTES", 128)

    with pytest.raises(ValueError, match="extended header exceeds"):
        inspect_sdist(sdist)


def test_sdist_rejects_hidden_gnu_sparse_pax_extensions(tmp_path: Path) -> None:
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        data = b"x"
        member = tarfile.TarInfo("agent_assure-0.6.4/member.txt")
        member.size = len(data)
        member.pax_headers = {
            "GNU.sparse.major": "1",
            "GNU.sparse.minor": "0",
        }
        archive.addfile(member, io.BytesIO(data))

    with pytest.raises(ValueError, match="GNU sparse PAX extensions"):
        inspect_sdist(sdist)


def test_required_sdist_paths_cover_installed_sources_and_resources() -> None:
    required = required_sdist_paths()

    assert "src/agent_assure/rag/sensitivity.py" in required
    assert "src/agent_assure/examples/process_equivalence_reproduction_index.json" in required
    assert (
        "src/agent_assure/examples/process_equivalence_benchmark_v0_2/benchmark.json"
        in required
    )
    assert "src/agent_assure/schema_resources/__init__.py" in required
    assert "schemas/__init__.py" not in required
    assert "schemas/v0.6.4/evidence-sensitivity-report.schema.json" in required
    assert "mappings/nist_ai_rmf.yaml" in required
    assert "pyproject.toml" in required


def test_distribution_identity_rejects_mismatched_wheel_and_sdist_versions(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "agent_assure-0.6.4.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n",
        )
    sdist = tmp_path / "agent_assure-9.9.9.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        _write_tar_member(
            archive,
            "agent_assure-9.9.9/PKG-INFO",
            "Metadata-Version: 2.4\nName: agent-assure\nVersion: 9.9.9\n",
        )

    with pytest.raises(ValueError, match="identity/version mismatch"):
        validate_distribution_identity(wheel, sdist)


def test_distribution_identity_rejects_mismatched_archive_layouts(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "other_project-0.6.4.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n",
        )
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        _write_tar_member(
            archive,
            "agent_assure-0.6.4/PKG-INFO",
            "Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n",
        )

    with pytest.raises(ValueError, match="identity/version mismatch"):
        validate_distribution_identity(wheel, sdist)


def test_distribution_identity_requires_record_in_matching_dist_info(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "agent_assure-0.6.4.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n",
        )
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        _write_tar_member(
            archive,
            "agent_assure-0.6.4/PKG-INFO",
            "Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n",
        )

    with pytest.raises(ValueError, match="exactly one .dist-info/RECORD"):
        validate_distribution_identity(wheel, sdist)


def test_inspect_wheel_verifies_record_digests(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    metadata_path = "agent_assure-0.6.4.dist-info/METADATA"
    record_path = "agent_assure-0.6.4.dist-info/RECORD"
    metadata = b"Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n"
    record = f"{metadata_path},sha256=invalid,{len(metadata)}\n{record_path},,\n"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(metadata_path, metadata)
        archive.writestr(record_path, record)

    with pytest.raises(ValueError, match="RECORD digest mismatch"):
        inspect_wheel(wheel)


@pytest.mark.parametrize(
    ("duplicate_line", "field_name"),
    (
        ("Name: attacker-project", "Name"),
        ("Summary: conflicting summary", "Summary"),
    ),
)
def test_metadata_identity_rejects_duplicate_single_use_core_metadata(
    duplicate_line: str,
    field_name: str,
) -> None:
    payload = (
        "Metadata-Version: 2.4\n"
        "Name: agent-assure\n"
        "Version: 0.6.4\n"
        "Summary: release validator\n"
        f"{duplicate_line}\n"
    ).encode()

    with pytest.raises(ValueError, match=rf"duplicate.*{field_name}"):
        _metadata_identity(payload, label="test METADATA")


@pytest.mark.parametrize(
    ("metadata_version", "field_name", "first_value", "second_value"),
    (
        ("2.4", "Provides-Extra", "adk", "otel"),
        ("2.5", "Import-Name", "agent_assure", "agent_assure.cli"),
        ("2.5", "Import-Namespace", "assurance_plugins", "assurance_extensions"),
    ),
)
def test_metadata_identity_accepts_specified_multiple_use_core_metadata_fields(
    metadata_version: str,
    field_name: str,
    first_value: str,
    second_value: str,
) -> None:
    payload = (
        f"Metadata-Version: {metadata_version}\n"
        "Name: agent-assure\n"
        "Version: 0.6.4\n"
        f"{field_name}: {first_value}\n"
        f"{field_name}: {second_value}\n"
    ).encode()

    assert _metadata_identity(payload, label="test METADATA") == (
        "agent-assure",
        "0.6.4",
    )


@pytest.mark.parametrize(
    ("missing_field", "expected_error"),
    (("hash", "requires sha256 digest"), ("size", "requires size")),
)
def test_inspect_wheel_requires_record_hash_and_size_for_ordinary_files(
    tmp_path: Path,
    missing_field: str,
    expected_error: str,
) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    metadata_path = "agent_assure-0.6.4.dist-info/METADATA"
    record_path = "agent_assure-0.6.4.dist-info/RECORD"
    metadata = b"Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n"
    digest = base64.urlsafe_b64encode(hashlib.sha256(metadata).digest()).rstrip(b"=").decode()
    digest_text = "" if missing_field == "hash" else f"sha256={digest}"
    size_text = "" if missing_field == "size" else str(len(metadata))
    record = f"{metadata_path},{digest_text},{size_text}\n{record_path},,\n"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(metadata_path, metadata)
        archive.writestr(record_path, record)

    with pytest.raises(ValueError, match=expected_error):
        inspect_wheel(wheel)


def test_required_wheel_file_cannot_be_satisfied_by_directory_entry(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    required_file = "agent_assure/__init__.py"
    entry = zipfile.ZipInfo(required_file)
    entry.create_system = 3
    entry.external_attr = (stat.S_IFDIR | 0o755) << 16
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(entry, b"")

    missing, forbidden = inspect_wheel(wheel)

    assert required_file in missing
    assert any("encoded as a directory" in item for item in forbidden)


def test_required_sdist_file_cannot_be_satisfied_by_directory_entry(tmp_path: Path) -> None:
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    required_file = "agent_assure-0.6.4/pyproject.toml"
    with tarfile.open(sdist, "w:gz") as archive:
        directory = tarfile.TarInfo(required_file)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)

    missing, _forbidden = inspect_sdist(sdist)

    assert "pyproject.toml" in missing


def test_distribution_directory_rejects_unexpected_files(tmp_path: Path) -> None:
    (tmp_path / "agent_assure-0.6.0-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "agent_assure-0.6.0.tar.gz").write_bytes(b"sdist")
    (tmp_path / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")

    try:
        validate_distribution_directory(tmp_path)
    except ValueError as exc:
        assert "unexpected distribution directory entries" in str(exc)
        assert "unexpected.txt" in str(exc)
    else:
        raise AssertionError("expected an extra distribution file to fail")


def test_distribution_directory_accepts_only_matching_signature_bundles(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "agent_assure-0.6.0-py3-none-any.whl"
    sdist = tmp_path / "agent_assure-0.6.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    wheel.with_name(f"{wheel.name}.bundle").write_text("bundle\n", encoding="utf-8")
    sdist.with_name(f"{sdist.name}.bundle").write_text("bundle\n", encoding="utf-8")

    assert validate_distribution_directory(tmp_path, allow_signature_bundles=True) == (wheel, sdist)


def test_distribution_payload_equivalence_maps_every_installable_source_byte(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_payload_pair(tmp_path)

    manifest = validate_distribution_payload_equivalence(
        wheel,
        sdist,
        schema_versions=("v0.6.4",),
    )

    assert manifest == {
        "agent_assure/__init__.py": hashlib.sha256(b"package\n").hexdigest(),
        "agent_assure/mappings/policy.yaml": hashlib.sha256(b"policy: synthetic\n").hexdigest(),
        "agent_assure/module.py": hashlib.sha256(b"VALUE = 1\n").hexdigest(),
        "agent_assure/schema_resources/v0.6.4/test.schema.json": hashlib.sha256(
            b"{}\n"
        ).hexdigest(),
    }


def test_wheel_privacy_scan_rejects_undecodable_binary_leak(tmp_path: Path) -> None:
    wheel, _sdist = _write_payload_pair(
        tmp_path,
        extra_wheel={
            "agent_assure/provider-response.bin": b"api_key=hunter2-value\xff",
        },
    )

    with pytest.raises(ValueError, match="closed text inventory|unsupported binary"):
        inspect_wheel(wheel)


def test_sdist_privacy_scan_rejects_undecodable_binary_leak(tmp_path: Path) -> None:
    _wheel, sdist = _write_payload_pair(
        tmp_path,
        extra_sdist={
            "src/agent_assure/provider-response.bin": b"api_key=hunter2-value\xff",
        },
    )

    with pytest.raises(ValueError, match="closed text inventory|unsupported binary"):
        inspect_sdist(sdist)


@pytest.mark.parametrize("archive_kind", ("wheel", "sdist"))
def test_distribution_privacy_scan_rejects_credential_literal_in_member_name(
    tmp_path: Path,
    archive_kind: str,
) -> None:
    credential_name = "sk-proj-abcdefghijklmnopqrstuvwxyz.py"
    wheel, sdist = _write_payload_pair(
        tmp_path,
        extra_wheel={f"agent_assure/{credential_name}": b"pass\n"},
        extra_sdist={f"src/agent_assure/{credential_name}": b"pass\n"},
    )

    with pytest.raises(ValueError, match="credential-literal privacy review"):
        (inspect_wheel(wheel) if archive_kind == "wheel" else inspect_sdist(sdist))


def test_release_scanner_allows_credential_handling_source_without_a_value(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_payload_pair(
        tmp_path,
        extra_sdist={
            "src/agent_assure/credential_handler.py": (
                b"def load(api_key_env):\n    return os.environ.get(api_key_env)\n"
            ),
        },
        extra_wheel={
            "agent_assure/credential_handler.py": (
                b"def load(api_key_env):\n    return os.environ.get(api_key_env)\n"
            ),
        },
    )

    inspect_wheel(wheel)
    inspect_sdist(sdist)


def test_sdist_sensitive_fixture_exception_is_bound_to_exact_path_and_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_path = "tests/unit/privacy/synthetic_detector_vector.py"
    approved = b"TOKEN = 'sk-proj-abcdefghijklmnopqrstuvwxyz'\n"
    monkeypatch.setitem(
        wheel_content_checks.SDIST_SENSITIVE_FIXTURE_SHA256,
        fixture_path,
        hashlib.sha256(approved).hexdigest(),
    )
    _wheel, sdist = _write_payload_pair(
        tmp_path,
        extra_sdist={fixture_path: approved},
    )

    inspect_sdist(sdist)

    _wheel, changed_sdist = _write_payload_pair(
        tmp_path,
        extra_sdist={fixture_path: approved + b"# changed\n"},
    )
    with pytest.raises(ValueError, match="credential-literal privacy review"):
        inspect_sdist(changed_sdist)


@pytest.mark.parametrize(
    "source",
    (
        b"settings.api_key = 'hunter2-value'\n",
        b"config['api_key'] = 'hunter2-value'\n",
        b"def connect(api_key='hunter2-value'):\n    return None\n",
        b"def connect(*, api_key='hunter2-value'):\n    return None\n",
    ),
)
def test_release_scanner_rejects_literal_credentials_in_complex_assignment_targets(
    tmp_path: Path,
    source: bytes,
) -> None:
    wheel, _sdist = _write_payload_pair(
        tmp_path,
        extra_wheel={"agent_assure/leaked.py": source},
    )

    with pytest.raises(ValueError, match="structural privacy review"):
        inspect_wheel(wheel)


def test_empty_unknown_wheel_member_still_fails_the_closed_inventory(tmp_path: Path) -> None:
    wheel, _sdist = _write_payload_pair(
        tmp_path,
        extra_wheel={"agent_assure/unknown.bin": b""},
    )

    with pytest.raises(ValueError, match="closed text inventory"):
        inspect_wheel(wheel)


@pytest.mark.parametrize(
    "metadata_kind",
    ("archive-comment", "member-comment", "member-extra"),
)
def test_wheel_metadata_cannot_carry_unscanned_bytes(
    tmp_path: Path,
    metadata_kind: str,
) -> None:
    wheel, _sdist = _write_payload_pair(tmp_path)
    with zipfile.ZipFile(wheel, "a") as archive:
        if metadata_kind == "archive-comment":
            archive.comment = b"sk-proj-abcdefghijklmnopqrstuvwxyz"
        else:
            info = zipfile.ZipInfo("agent_assure/metadata_channel.py")
            if metadata_kind == "member-comment":
                info.comment = b"sk-proj-abcdefghijklmnopqrstuvwxyz"
            else:
                secret = b"sk-proj-abcdefghijklmnopqrstuvwxyz"
                info.extra = struct.pack("<HH", 0xCAFE, len(secret)) + secret
            archive.writestr(info, b"pass\n")

    with pytest.raises(ValueError, match="comments|extra fields"):
        inspect_wheel(wheel)


@pytest.mark.parametrize(
    "metadata_kind",
    ("global-pax", "member-pax", "uname"),
)
def test_sdist_metadata_cannot_carry_unscanned_bytes(
    tmp_path: Path,
    metadata_kind: str,
) -> None:
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    global_headers = (
        {"comment": "sk-proj-abcdefghijklmnopqrstuvwxyz"}
        if metadata_kind == "global-pax"
        else None
    )
    with tarfile.open(
        sdist,
        "w:gz",
        format=tarfile.PAX_FORMAT,
        pax_headers=global_headers,
    ) as archive:
        data = b"safe\n"
        info = tarfile.TarInfo("agent_assure-0.6.4/README.md")
        info.size = len(data)
        if metadata_kind == "member-pax":
            info.pax_headers = {"comment": "sk-proj-abcdefghijklmnopqrstuvwxyz"}
        elif metadata_kind == "uname":
            info.uname = "sk-proj-abcdefghijklmnopqrstuvwxyz"
        archive.addfile(info, io.BytesIO(data))

    with pytest.raises(ValueError, match="PAX metadata|identity and link metadata"):
        inspect_sdist(sdist)


@pytest.mark.parametrize(
    "unexpected_path",
    (
        "bootstrap.pth",
        "agent_assure-0.6.4.data/purelib/bootstrap.pth",
        "agent_assure/extra_module.py",
    ),
)
def test_distribution_payload_equivalence_rejects_wheel_only_payloads(
    tmp_path: Path,
    unexpected_path: str,
) -> None:
    wheel, sdist = _write_payload_pair(
        tmp_path,
        extra_wheel={unexpected_path: b"import attacker\n"},
    )

    with pytest.raises(ValueError, match="unexpected in wheel"):
        validate_distribution_payload_equivalence(
            wheel,
            sdist,
            schema_versions=("v0.6.4",),
        )


def test_distribution_payload_equivalence_rejects_sdist_only_installable_source(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_payload_pair(
        tmp_path,
        extra_sdist={"src/agent_assure/missing.py": b"MISSING = True\n"},
    )

    with pytest.raises(ValueError, match="missing from wheel=.*agent_assure/missing.py"):
        validate_distribution_payload_equivalence(
            wheel,
            sdist,
            schema_versions=("v0.6.4",),
        )


def test_distribution_payload_equivalence_rejects_same_size_byte_drift(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_payload_pair(
        tmp_path,
        wheel_overrides={"agent_assure/module.py": b"VALUE = 2\n"},
    )

    with pytest.raises(ValueError, match="payload bytes differ: agent_assure/module.py"):
        validate_distribution_payload_equivalence(
            wheel,
            sdist,
            schema_versions=("v0.6.4",),
        )


def test_distribution_payload_equivalence_reads_reverse_order_tar_once_in_archive_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agent_assure/a.py", b"A\n")
        archive.writestr("agent_assure/z.py", b"Z\n")
    sdist = tmp_path / "agent_assure-0.6.4.tar.gz"
    with tarfile.open(sdist, "w:gz") as tar_archive:
        _write_binary_tar_member(
            tar_archive,
            "agent_assure-0.6.4/src/agent_assure/z.py",
            b"Z\n",
        )
        _write_binary_tar_member(
            tar_archive,
            "agent_assure-0.6.4/src/agent_assure/a.py",
            b"A\n",
        )
    observed: list[str] = []
    original = wheel_content_checks._read_tar_member_bytes

    def record_read(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
        observed.append(member.name)
        return original(archive, member)

    monkeypatch.setattr(wheel_content_checks, "_read_tar_member_bytes", record_read)

    validate_distribution_payload_equivalence(
        wheel,
        sdist,
        schema_versions=("v0.6.4",),
    )

    assert observed == [
        "agent_assure-0.6.4/src/agent_assure/z.py",
        "agent_assure-0.6.4/src/agent_assure/a.py",
    ]


def test_independently_built_wheel_requires_full_metadata_and_payload_equivalence(
    tmp_path: Path,
) -> None:
    reference = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    candidate = tmp_path / "candidate-agent_assure-0.6.4-py3-none-any.whl"
    for path, summary in ((reference, "trusted"), (candidate, "drifted")):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("agent_assure/__init__.py", b"package\n")
            archive.writestr(
                "agent_assure-0.6.4.dist-info/METADATA",
                (
                    "Metadata-Version: 2.4\n"
                    "Name: agent-assure\n"
                    "Version: 0.6.4\n"
                    f"Summary: {summary}\n"
                ),
            )

    with pytest.raises(ValueError, match="member bytes differ.*METADATA"):
        validate_wheel_archive_equivalence(reference, candidate)


def _write_payload_pair(
    directory: Path,
    *,
    extra_wheel: dict[str, bytes] | None = None,
    extra_sdist: dict[str, bytes] | None = None,
    wheel_overrides: dict[str, bytes] | None = None,
) -> tuple[Path, Path]:
    source_payloads = {
        "src/agent_assure/__init__.py": b"package\n",
        "src/agent_assure/module.py": b"VALUE = 1\n",
        "mappings/policy.yaml": b"policy: synthetic\n",
        "schemas/v0.6.4/test.schema.json": b"{}\n",
    }
    source_payloads.update(extra_sdist or {})
    mapped_payloads = {
        "agent_assure/__init__.py": source_payloads["src/agent_assure/__init__.py"],
        "agent_assure/module.py": source_payloads["src/agent_assure/module.py"],
        "agent_assure/mappings/policy.yaml": source_payloads["mappings/policy.yaml"],
        "agent_assure/schema_resources/v0.6.4/test.schema.json": source_payloads[
            "schemas/v0.6.4/test.schema.json"
        ],
    }
    mapped_payloads.update(wheel_overrides or {})
    mapped_payloads.update(extra_wheel or {})

    wheel = directory / "agent_assure-0.6.4-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in sorted(mapped_payloads.items()):
            archive.writestr(name, data)
        archive.writestr(
            "agent_assure-0.6.4.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n",
        )

    sdist = directory / "agent_assure-0.6.4.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, data in sorted(source_payloads.items()):
            _write_binary_tar_member(archive, f"agent_assure-0.6.4/{name}", data)
        _write_tar_member(
            archive,
            "agent_assure-0.6.4/PKG-INFO",
            "Metadata-Version: 2.4\nName: agent-assure\nVersion: 0.6.4\n",
        )
        _write_tar_member(archive, "agent_assure-0.6.4/README.md", "ignored\n")
    return wheel, sdist


def _write_tar_member(archive: tarfile.TarFile, name: str, content: str) -> None:
    _write_binary_tar_member(archive, name, content.encode("utf-8"))


def _write_binary_tar_member(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))
