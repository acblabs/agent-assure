from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.smoke_install_wheel as smoke_install
from agent_assure.demo.evidence_sensitivity import run_evidence_sensitivity_demo
from agent_assure.rag.sensitivity import (
    execute_sensitivity_experiment,
    write_sensitivity_artifacts,
)
from agent_assure.schema.sensitivity import EvidenceSensitivityExpectedRelation
from scripts.smoke_install_wheel import (
    _demo_network_guard_assertion,
    _installed_evidence_reversed_assertion,
    _installed_evidence_sensitivity_demo_assertion,
    _installed_wheel_campaign_assertion,
    _packaged_example_assertion,
)

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_SENSITIVITY_EXAMPLE = ROOT / "examples" / "evidence_sensitivity"


def test_install_exact_distribution_is_offline_no_dependency_and_no_compile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = wheelhouse / "agent_assure-0.6.4-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "agent_assure-0.6.4.dist-info/METADATA",
            (
                "Metadata-Version: 2.4\n"
                "Name: agent-assure\n"
                "Version: 0.6.4\n"
                "Requires-Dist: attacker @ https://attacker.invalid/code.whl\n"
            ),
        )
    wheel_snapshot = smoke_install.capture_file_snapshot(
        wheel,
        max_bytes=1024,
        label="test wheel",
    )
    calls: list[list[str]] = []

    def capture(args: list[str], *, cwd: Path, **_kwargs: object) -> None:
        assert cwd == tmp_path
        calls.append(args)

    monkeypatch.setattr(smoke_install, "run", capture)

    smoke_install.install_exact_distribution(
        tmp_path / "python",
        wheelhouse,
        wheel,
        expected_snapshot=wheel_snapshot,
        cwd=tmp_path,
    )
    assert calls == [
        [
            str(tmp_path / "python"),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--no-deps",
            "--no-compile",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            str(wheel),
        ]
    ]

    assert "--no-deps" in calls[0]
    assert "--no-compile" in calls[0]
    assert "--require-hashes" not in calls[0]


def test_install_exact_distribution_detects_artifact_mutation_during_pip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = tmp_path / "artifact" / "agent_assure-0.6.4-py3-none-any.whl"
    wheel.parent.mkdir()
    wheel.write_bytes(b"trusted-wheel")
    snapshot = smoke_install.capture_file_snapshot(
        wheel,
        max_bytes=1024,
        label="test wheel",
    )

    def mutate(_args: list[str], *, cwd: Path, **_kwargs: object) -> None:
        assert cwd == tmp_path
        wheel.write_bytes(b"substituted-wheel")

    monkeypatch.setattr(smoke_install, "run", mutate)

    with pytest.raises(ValueError, match="materialized distribution bytes changed"):
        smoke_install.install_exact_distribution(
            tmp_path / "python",
            wheelhouse,
            wheel,
            expected_snapshot=snapshot,
            cwd=tmp_path,
        )


def test_locked_dependencies_require_hashes_and_disable_transitive_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    lockfile = tmp_path / "requirements.lock"
    lockfile.write_text("demo==1 --hash=sha256:" + ("a" * 64) + "\n", encoding="utf-8")
    calls: list[list[str]] = []

    def capture(args: list[str], *, cwd: Path, **_kwargs: object) -> None:
        assert cwd == tmp_path
        calls.append(args)

    monkeypatch.setattr(smoke_install, "run", capture)

    smoke_install.install_locked_dependencies(
        tmp_path / "python",
        wheelhouse,
        lockfile,
        cwd=tmp_path,
    )

    assert len(calls) == 1
    command = calls[0]
    assert "--require-hashes" in command
    assert "--no-deps" in command
    assert "--no-compile" in command
    assert "--no-index" in command
    assert command[-2:] == ["-r", str(lockfile)]


def test_materialized_snapshot_is_exact_and_exclusive(tmp_path: Path) -> None:
    source = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    source.write_bytes(b"exact-wheel-bytes")
    snapshot = smoke_install.capture_file_snapshot(
        source,
        max_bytes=1024,
        label="test wheel",
    )
    destination = smoke_install.materialize_snapshot(snapshot, tmp_path / "stage")

    smoke_install.assert_snapshot_unchanged(destination, snapshot)
    with pytest.raises(FileExistsError):
        smoke_install.materialize_snapshot(snapshot, tmp_path / "stage")


def test_preplanted_snapshot_destination_symlink_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    source.write_bytes(b"trusted")
    snapshot = smoke_install.capture_file_snapshot(
        source,
        max_bytes=1024,
        label="test wheel",
    )
    target = tmp_path / "attacker-target"
    target.mkdir()
    link = tmp_path / "preplanted"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable in this test environment: {exc}")

    with pytest.raises(ValueError, match="not a regular directory"):
        smoke_install.materialize_snapshot(snapshot, link, prepared=True)


def test_preplanted_snapshot_destination_reparse_point_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "preplanted"
    destination.mkdir()
    metadata = os.lstat(destination)
    fake_metadata = SimpleNamespace(
        st_mode=metadata.st_mode | stat.S_IFDIR,
        st_file_attributes=smoke_install._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
    )
    monkeypatch.setattr(os, "lstat", lambda _path: fake_metadata)

    with pytest.raises(ValueError, match="not a regular directory"):
        smoke_install._require_regular_directory(destination, label="test destination")


@pytest.mark.skipif(os.name != "posix", reason="CPython lib64 aliases are POSIX-only")
def test_tree_snapshot_records_only_the_exact_cpython_venv_alias(tmp_path: Path) -> None:
    phase = tmp_path / "phase"
    library = phase / "venv" / "lib"
    library.mkdir(parents=True)
    alias = phase / "venv" / "lib64"
    alias.symlink_to("lib", target_is_directory=True)

    with pytest.raises(ValueError, match="link or reparse point"):
        smoke_install.capture_tree_snapshot(phase, label="test environment")

    snapshot = smoke_install.capture_tree_snapshot(
        phase,
        label="test environment",
        allowed_directory_links={"venv/lib64": "lib"},
    )

    assert snapshot.links == {"venv/lib64": "lib"}
    assert "venv/lib64" not in snapshot.directories

    alias.unlink()
    with pytest.raises(ValueError, match="test environment changed"):
        smoke_install.assert_tree_snapshot_unchanged(
            phase,
            snapshot,
            label="test environment",
        )


@pytest.mark.skipif(os.name != "posix", reason="CPython lib64 aliases are POSIX-only")
@pytest.mark.parametrize("target", ("other", "../outside", "/tmp/outside"))
def test_tree_snapshot_rejects_unexpected_cpython_venv_alias_targets(
    tmp_path: Path,
    target: str,
) -> None:
    phase = tmp_path / "phase"
    library = phase / "venv" / "lib"
    library.mkdir(parents=True)
    (phase / "venv" / "lib64").symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="unexpected directory link target"):
        smoke_install.capture_tree_snapshot(
            phase,
            label="test environment",
            allowed_directory_links={"venv/lib64": "lib"},
        )


@pytest.mark.skipif(os.name != "posix", reason="CPython lib64 aliases are POSIX-only")
def test_tree_snapshot_rejects_links_beyond_the_cpython_venv_alias(tmp_path: Path) -> None:
    phase = tmp_path / "phase"
    library = phase / "venv" / "lib"
    library.mkdir(parents=True)
    (phase / "venv" / "lib64").symlink_to("lib", target_is_directory=True)
    (phase / "venv" / "extra").symlink_to("lib", target_is_directory=True)

    with pytest.raises(ValueError, match=r"link or reparse point: venv/extra"):
        smoke_install.capture_tree_snapshot(
            phase,
            label="test environment",
            allowed_directory_links={"venv/lib64": "lib"},
        )


def test_install_delta_rejects_virtualenv_directory_link_changes(tmp_path: Path) -> None:
    before = smoke_install.TreeSnapshot(
        directories=frozenset(),
        files={},
        links={"venv/lib64": "lib"},
    )
    after = smoke_install.TreeSnapshot(directories=frozenset(), files={})

    with pytest.raises(ValueError, match="changed virtualenv directory links"):
        smoke_install.validate_project_install_delta(
            before,
            after,
            environment_root=tmp_path,
            layout=smoke_install.EnvironmentLayout(purelib="lib", scripts="bin"),
            wheel=tmp_path / "missing.whl",
            wheel_snapshot=smoke_install.DistributionSnapshot(
                name="missing.whl",
                data=b"",
                sha256=hashlib.sha256(b"").hexdigest(),
            ),
            label="test install",
        )


def test_full_environment_delta_rejects_pth_and_sourceless_pyc_injection(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "agent_assure-0.6.4-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agent_assure-0.6.4.dist-info/RECORD", "")
    wheel_snapshot = smoke_install.capture_file_snapshot(
        wheel,
        max_bytes=1024 * 1024,
        label="test wheel",
    )
    before = smoke_install.TreeSnapshot(directories=frozenset(), files={})
    after = smoke_install.TreeSnapshot(
        directories=frozenset({"Lib", "Lib/site-packages"}),
        files={
            "Lib/site-packages/bootstrap.pth": smoke_install.TreeFile(
                size=16,
                sha256="a" * 64,
            ),
            "Lib/site-packages/evil.pyc": smoke_install.TreeFile(
                size=32,
                sha256="b" * 64,
            ),
        },
    )

    with pytest.raises(ValueError, match="full install inventory mismatch") as raised:
        smoke_install.validate_project_install_delta(
            before,
            after,
            environment_root=tmp_path,
            layout=smoke_install.EnvironmentLayout(
                purelib="Lib/site-packages",
                scripts="Scripts",
            ),
            wheel=wheel,
            wheel_snapshot=wheel_snapshot,
            label="adversarial install",
        )

    assert "bootstrap.pth" in str(raised.value)
    assert "evil.pyc" in str(raised.value)


def test_installed_payload_assertion_accepts_exact_files_and_ignores_bytecode(
    tmp_path: Path,
) -> None:
    package, assertion, env = _installed_payload_test_case(tmp_path)
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "module.cpython-test.pyc").write_bytes(b"ignored bytecode")

    result = subprocess.run(
        [sys.executable, "-c", assertion],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def test_installed_payload_assertion_rejects_digest_drift(tmp_path: Path) -> None:
    package, assertion, env = _installed_payload_test_case(tmp_path)
    (package / "module.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-c", assertion],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "payload digest mismatch" in result.stderr


def test_installed_payload_assertion_rejects_unexpected_regular_file(tmp_path: Path) -> None:
    package, assertion, env = _installed_payload_test_case(tmp_path)
    (package / "unexpected.py").write_text("ATTACK = True\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-c", assertion],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "unexpected file" in result.stderr


def test_installed_payload_assertion_rejects_symlinks(tmp_path: Path) -> None:
    package, assertion, env = _installed_payload_test_case(tmp_path)
    try:
        (package / "linked.py").symlink_to(package / "module.py")
    except OSError as exc:
        pytest.skip(f"symlinks unavailable in this test environment: {exc}")

    result = subprocess.run(
        [sys.executable, "-c", assertion],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "link or reparse point" in result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO files are unavailable")
def test_installed_payload_assertion_rejects_nonregular_files(tmp_path: Path) -> None:
    package, assertion, env = _installed_payload_test_case(tmp_path)
    os.__dict__["mkfifo"](package / "named-pipe")

    result = subprocess.run(
        [sys.executable, "-c", assertion],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "non-regular file" in result.stderr


def test_demo_network_guard_assertion_blocks_socket_in_child(tmp_path: Path) -> None:
    env = os.environ.copy()
    pythonpath = [str(ROOT / "src")]
    if env.get("PYTHONPATH"):
        pythonpath.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)

    result = subprocess.run(
        [sys.executable, "-c", _demo_network_guard_assertion()],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def test_installed_wheel_campaign_assertion_runs_without_network(
    tmp_path: Path,
) -> None:
    env = os.environ.copy()
    pythonpath = [str(ROOT / "src")]
    if env.get("PYTHONPATH"):
        pythonpath.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)

    result = subprocess.run(
        [sys.executable, "-c", _installed_wheel_campaign_assertion()],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def test_packaged_example_assertion_includes_evidence_sensitivity_resources(
    tmp_path: Path,
) -> None:
    assertion = _packaged_example_assertion()
    assert "evidence_sensitivity/evidence_reversed_suite.yaml" in assertion
    for fixture_kind in ("requests", "model_outputs", "tool_outputs"):
        assert (
            "evidence_sensitivity/fixtures/evidence_reversed/"
            f"{fixture_kind}/synthetic-benefit-eligibility.json"
        ) in assertion
    result = subprocess.run(
        [sys.executable, "-c", assertion],
        cwd=tmp_path,
        env=_source_environment(),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def test_installed_evidence_sensitivity_demo_assertion_validates_demo(
    tmp_path: Path,
) -> None:
    out = tmp_path / "evidence-sensitivity"
    summary = run_evidence_sensitivity_demo(out, clean=True)
    assert summary["status"] == "success"

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _installed_evidence_sensitivity_demo_assertion(out),
        ],
        cwd=tmp_path,
        env=_source_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def test_installed_evidence_reversed_assertion_validates_wrong_flip(
    tmp_path: Path,
) -> None:
    out = tmp_path / "evidence-reversed"
    artifacts = execute_sensitivity_experiment(
        suite_path=EVIDENCE_SENSITIVITY_EXAMPLE / "evidence_reversed_suite.yaml",
        baseline_corpus_dir=EVIDENCE_SENSITIVITY_EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EVIDENCE_SENSITIVITY_EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EVIDENCE_SENSITIVITY_EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    write_sensitivity_artifacts(artifacts, out)

    result = subprocess.run(
        [sys.executable, "-c", _installed_evidence_reversed_assertion(out)],
        cwd=tmp_path,
        env=_source_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def _source_environment() -> dict[str, str]:
    env = os.environ.copy()
    pythonpath = [str(ROOT / "src")]
    if env.get("PYTHONPATH"):
        pythonpath.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    return env


def _installed_payload_test_case(
    tmp_path: Path,
) -> tuple[Path, str, dict[str, str]]:
    site_root = tmp_path / "isolated-prefix"
    package = site_root / "agent_assure"
    package.mkdir(parents=True)
    payloads = {
        "agent_assure/__init__.py": b"PACKAGE = True\n",
        "agent_assure/module.py": b"VALUE = 1\n",
    }
    for name, data in payloads.items():
        destination = site_root / Path(*name.split("/"))
        destination.write_bytes(data)
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}
    snapshot = smoke_install.distribution_payload_manifest_snapshot(manifest)
    manifest_path = smoke_install.materialize_snapshot(snapshot, tmp_path / "manifest")
    assertion = (
        f"import sys\nsys.prefix = {str(site_root)!r}\n"
        + smoke_install._installed_package_payload_assertion(manifest_path, snapshot)
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(site_root)
    env["PYTHONNOUSERSITE"] = "1"
    return package, assertion, env
