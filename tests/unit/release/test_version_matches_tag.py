from __future__ import annotations

from pathlib import Path

import scripts.check_version_matches_tag as version_tag


def test_version_tag_check_accepts_matching_package_schema_and_frozen_dir(
    tmp_path: Path,
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
    )

    result = version_tag.main(
        [
            "v1.2.3",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 0


def test_version_tag_check_rejects_schema_version_mismatch(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.4",
        base_schema_version="1.2.3",
    )

    result = version_tag.main(
        [
            "v1.2.3",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 1


def test_version_tag_check_allows_release_candidate_with_base_schema(
    tmp_path: Path,
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3rc1",
        package_version="1.2.3rc1",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
        schema_dir_version="1.2.3",
    )

    result = version_tag.main(
        [
            "v1.2.3rc1",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 0


def test_version_tag_check_rejects_missing_frozen_schema_dir(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
        create_schema_dir=False,
    )

    result = version_tag.main(
        [
            "v1.2.3",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 1


def _write_version_files(
    tmp_path: Path,
    *,
    project_version: str,
    package_version: str,
    package_schema_version: str,
    base_schema_version: str,
    create_schema_dir: bool = True,
    schema_dir_version: str | None = None,
) -> tuple[Path, Path, Path, Path]:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        f"[project]\nversion = {project_version!r}\n",
        encoding="utf-8",
    )
    package_init = tmp_path / "__init__.py"
    package_init.write_text(
        f"__version__ = {package_version!r}\n"
        f"SCHEMA_VERSION = {package_schema_version!r}\n",
        encoding="utf-8",
    )
    schema_base = tmp_path / "base.py"
    schema_base.write_text(
        f"SCHEMA_VERSION = {base_schema_version!r}\n",
        encoding="utf-8",
    )
    schema_root = tmp_path / "schemas"
    if create_schema_dir:
        (schema_root / f"v{schema_dir_version or project_version}").mkdir(parents=True)
    return pyproject, package_init, schema_base, schema_root
