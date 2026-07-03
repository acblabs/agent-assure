from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from check_version_matches_tag import main, normalize_tag  # noqa: E402


def test_normalize_tag_accepts_github_ref() -> None:
    assert normalize_tag("refs/tags/v0.3.0") == "v0.3.0"


def test_normalize_tag_accepts_release_candidate() -> None:
    assert normalize_tag("refs/tags/v0.3.0rc1") == "v0.3.0rc1"


def test_normalize_tag_rejects_shell_syntax() -> None:
    try:
        normalize_tag('refs/tags/v0.3.0"; echo injected')
    except ValueError as exc:
        assert "must match" in str(exc)
    else:
        raise AssertionError("expected malicious-looking tag to be rejected")


def test_version_tag_check_accepts_matching_metadata(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        "0.3.0",
        "0.3.0",
        "0.3.0",
    )

    status = main(
        [
            "v0.3.0",
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

    assert status == 0


def test_version_tag_check_accepts_release_candidate_metadata(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        "0.3.0rc1",
        "0.3.0rc1",
        "0.3.0",
        schema_dir_version="0.3.0",
    )

    status = main(
        [
            "v0.3.0rc1",
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

    assert status == 0


def test_version_tag_check_rejects_mismatched_tag(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        "0.3.0",
        "0.3.0",
        "0.3.0",
    )

    status = main(
        [
            "v0.2.0",
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

    assert status == 1


def test_version_tag_check_rejects_package_version_drift(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        "0.3.0",
        "0.2.0",
        "0.3.0",
    )

    status = main(
        [
            "v0.3.0",
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

    assert status == 1


def _write_version_files(
    tmp_path: Path,
    pyproject_version: str,
    package_version: str,
    schema_version: str,
    *,
    schema_dir_version: str | None = None,
) -> tuple[Path, Path, Path, Path]:
    pyproject = tmp_path / "pyproject.toml"
    package_init = tmp_path / "__init__.py"
    schema_base = tmp_path / "base.py"
    schema_root = tmp_path / "schemas"
    pyproject.write_text(
        f'[project]\nname = "agent-assure"\nversion = "{pyproject_version}"\n',
        encoding="utf-8",
    )
    package_init.write_text(
        f'__version__ = "{package_version}"\nSCHEMA_VERSION = "{schema_version}"\n',
        encoding="utf-8",
    )
    schema_base.write_text(f'SCHEMA_VERSION = "{schema_version}"\n', encoding="utf-8")
    (schema_root / f"v{schema_dir_version or schema_version}").mkdir(parents=True)
    return pyproject, package_init, schema_base, schema_root
