from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from scripts.check_wheel_contents import inspect_sdist, inspect_wheel, required_archive_paths
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
    assert (
        "agent_assure/examples/prior_auth_synthetic/fixtures/rag/"
        "counterfactual_query_families.json"
    ) in required
    assert "agent_assure/mappings/nist_ai_rmf.yaml" in required
    assert "agent_assure/mappings/mitre_atlas_2026_06.yaml" in required
    assert "agent_assure/examples/langgraph_expense_assurance/runner.py" in required
    assert "agent_assure/examples/langgraph_expense_assurance/suite.yaml" in required


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

    forbidden = inspect_sdist(sdist)

    assert "agent_assure-0.3.1/schemas/unreleased/usage-summary.schema.json" in forbidden


def _write_tar_member(archive: tarfile.TarFile, name: str, content: str) -> None:
    data = content.encode("utf-8")
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))
