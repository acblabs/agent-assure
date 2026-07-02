from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
LOCKFILE = ROOT / "requirements.lock"
SCHEMA_ROOT = ROOT / "schemas"
FROZEN_SCHEMA_VERSIONS = ("v0.1.0", "v0.2.0", "v0.3.0")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        wheel = find_single_wheel(args.dist)
        with tempfile.TemporaryDirectory(prefix="agent-assure-wheel-smoke-") as temp:
            temp_dir = Path(temp)
            venv_dir = temp_dir / ".venv"
            wheelhouse = temp_dir / "wheelhouse"
            schema_dir = temp_dir / "schemas"
            flagship_dir = temp_dir / "flagship"
            build_wheelhouse(args.dist, wheelhouse, args.lockfile)
            create_virtualenv(venv_dir)
            python = venv_python(venv_dir)
            agent_assure = venv_executable(venv_dir, "agent-assure")

            run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-index",
                    "--find-links",
                    str(wheelhouse),
                    "agent-assure",
                ],
                cwd=temp_dir,
            )
            run(
                [
                    str(python),
                    "-c",
                    _wheel_import_assertion(venv_dir),
                ],
                cwd=temp_dir,
            )
            run(
                [
                    str(python),
                    "-c",
                    _packaged_example_assertion(),
                ],
                cwd=temp_dir,
            )
            run(
                [
                    str(python),
                    "-c",
                    _packaged_schema_resource_assertion(),
                ],
                cwd=temp_dir,
            )
            run([str(agent_assure), "--version"], cwd=temp_dir)
            run(
                [str(agent_assure), "schema", "export", "--out", str(schema_dir)],
                cwd=temp_dir,
            )
            run(
                [
                    str(agent_assure),
                    "demo",
                    "flagship",
                    "--out",
                    str(flagship_dir),
                    "--clean",
                ],
                cwd=temp_dir,
            )
    except (RuntimeError, ValueError) as exc:
        print(f"wheel-smoke: {exc}", file=sys.stderr)
        return 1

    print(f"wheel-smoke: ok ({wheel.name})")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install and smoke test the local wheel.")
    parser.add_argument(
        "--dist",
        type=Path,
        default=DIST,
        help="Directory containing exactly one built wheel. Defaults to dist/.",
    )
    parser.add_argument(
        "--lockfile",
        type=Path,
        default=LOCKFILE,
        help="Hash-locked dependency file used to populate the local wheelhouse.",
    )
    return parser.parse_args(argv)


def find_single_wheel(dist_dir: Path) -> Path:
    wheels = sorted(dist_dir.glob("*.whl"))
    if len(wheels) != 1:
        wheel_list = ", ".join(wheel.name for wheel in wheels) or "none"
        raise ValueError(f"expected exactly one wheel in {dist_dir}, found {wheel_list}")
    return wheels[0]


def build_wheelhouse(dist_dir: Path, wheelhouse: Path, lockfile: Path) -> None:
    wheelhouse.mkdir(parents=True, exist_ok=True)
    for artifact in dist_dir.iterdir():
        if artifact.is_file():
            shutil.copy2(artifact, wheelhouse / artifact.name)
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--disable-pip-version-check",
            "--require-hashes",
            "--only-binary",
            ":all:",
            "--dest",
            str(wheelhouse),
            "-r",
            str(lockfile),
        ]
    )


def create_virtualenv(venv_dir: Path) -> None:
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(venv_dir)


def venv_python(venv_dir: Path) -> Path:
    return venv_executable(venv_dir, "python")


def venv_executable(venv_dir: Path, name: str) -> Path:
    script_dir = "Scripts" if os.name == "nt" else "bin"
    suffix = ".exe" if os.name == "nt" else ""
    return venv_dir / script_dir / f"{name}{suffix}"


def run(args: list[str], *, cwd: Path = ROOT) -> None:
    env = {**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return
    command = " ".join(args)
    details = "\n".join(
        part
        for part in (
            f"command failed with exit {result.returncode}: {command}",
            result.stdout.strip(),
            result.stderr.strip(),
        )
        if part
    )
    raise RuntimeError(details)


def _wheel_import_assertion(venv_dir: Path) -> str:
    expected_prefix = str(venv_dir.resolve())
    return (
        "from pathlib import Path; "
        "import agent_assure; "
        f"expected = Path({expected_prefix!r}); "
        "actual = Path(agent_assure.__file__).resolve(); "
        "actual.relative_to(expected)"
    )


def _packaged_example_assertion() -> str:
    required = (
        "prior_auth_synthetic/suite.yaml",
        "prior_auth_synthetic/variants/baseline.yaml",
        "prior_auth_synthetic/variants/candidate_evidence_normalization.yaml",
        "prior_auth_synthetic/fixtures/shared/requests/shared-source-multi-claim.json",
        "expense_approval_minimal/suite.yaml",
        "expense_approval_minimal/variants/baseline.yaml",
        "expense_approval_minimal/variants/candidate_provider_policy.yaml",
        "expense_approval_minimal/fixtures/shared/requests/exp-001.json",
    )
    return (
        "from importlib.resources import files; "
        f"required = {required!r}; "
        "root = files('agent_assure.examples'); "
        "missing = [name for name in required if not root.joinpath(name).is_file()]; "
        "raise SystemExit('missing packaged examples: ' + ', '.join(missing) if missing else 0)"
    )


def _packaged_schema_resource_assertion() -> str:
    required = _frozen_schema_resource_paths()
    return (
        "from importlib.resources import files; "
        f"required = {required!r}; "
        "root = files('agent_assure.schema_resources'); "
        "missing = [name for name in required if not root.joinpath(name).is_file()]; "
        "raise SystemExit('missing packaged schema resources: ' + ', '.join(missing) "
        "if missing else 0)"
    )


def _frozen_schema_resource_paths(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] = FROZEN_SCHEMA_VERSIONS,
) -> tuple[str, ...]:
    paths: list[str] = []
    for version in schema_versions:
        version_dir = schema_root / version
        paths.extend(
            f"{version}/{path.name}"
            for path in sorted(version_dir.glob("*.schema.json"))
        )
    return tuple(paths)


if __name__ == "__main__":
    raise SystemExit(main())
