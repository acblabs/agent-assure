from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_assure import __version__
from agent_assure.artifact_io import file_sha256
from agent_assure.cli import controls_cmd, init_cmd
from agent_assure.cli.main import app
from agent_assure.evaluation import evaluator
from agent_assure.mutation import campaign, execution
from agent_assure.mutation.catalog import CatalogIntegrityError
from agent_assure.onboarding import (
    controls_mutation,
    controls_mutation_config,
    controls_mutation_doctor,
    controls_mutation_scaffold,
)
from agent_assure.onboarding.controls_mutation import (
    CONFIG_FILENAME,
    DEFAULT_SCAFFOLD_DIRECTORY,
    MANAGED_FILENAMES,
    ControlsMutationOnboardingConfig,
    DiagnosticStatus,
    DoctorCode,
    ScaffoldConflictError,
    diagnose_controls_mutate,
    expected_scaffold_files,
    load_controls_mutation_config,
    load_controls_mutation_config_snapshot,
    parse_controls_mutation_config,
    require_confined_input_directory,
    scaffold_controls_mutation,
)
from agent_assure.onboarding.diagnostics import bounded_error, display_path

_RUNNER = CliRunner()


def test_facade_preserves_public_type_identity_and_scaffold_bytes() -> None:
    facade_module = "agent_assure.onboarding.controls_mutation"
    facade_types = (
        controls_mutation.ScaffoldConflictError,
        controls_mutation.ControlsMutationOnboardingConfig,
        controls_mutation.ScaffoldResult,
        controls_mutation.ControlsMutationInputBinding,
        controls_mutation.DiagnosticStatus,
        controls_mutation.DoctorDiagnostic,
        controls_mutation.DoctorReport,
        controls_mutation.DoctorCode,
    )

    assert all(item.__module__ == facade_module for item in facade_types)
    assert (
        controls_mutation_config.ControlsMutationOnboardingConfig
        is controls_mutation.ControlsMutationOnboardingConfig
    )
    assert (
        controls_mutation_config.ControlsMutationInputBinding
        is controls_mutation.ControlsMutationInputBinding
    )
    assert (
        controls_mutation_scaffold.ScaffoldConflictError is controls_mutation.ScaffoldConflictError
    )
    assert controls_mutation_scaffold.ScaffoldResult is controls_mutation.ScaffoldResult
    assert controls_mutation_doctor.DiagnosticStatus is controls_mutation.DiagnosticStatus
    assert controls_mutation_doctor.DoctorDiagnostic is controls_mutation.DoctorDiagnostic
    assert controls_mutation_doctor.DoctorReport is controls_mutation.DoctorReport
    assert controls_mutation_doctor.DoctorCode is controls_mutation.DoctorCode

    expected_hashes = {
        "controls-mutation.yaml": (
            747,
            "c2b3ec3b95b56711c05591421acaa1a186859c31a15f45b6bfb700d49d1bb102",
        ),
        "suite.yaml": (
            318,
            "52fc481863cb45d8089a5d88eaea580b171c3ab29cd861b95f1760cda5e9b549",
        ),
        "runset.json": (
            3610,
            "7b18a72462b2ce8fba13bccc1b96a9b3a1b5eb41ebe94adb56e32aec0e93869e",
        ),
        "threat-applicability.yaml": (
            685,
            "35b276937d2d7586e6c8a649622916893eafeb8e5acf5e2013bb852c8f64c902",
        ),
    }
    actual_hashes = {
        name: (len(contents), hashlib.sha256(contents).hexdigest())
        for name, contents in expected_scaffold_files().items()
    }

    assert actual_hashes == expected_hashes


def test_split_modules_preserve_type_identity_across_fresh_import_orders() -> None:
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    pythonpath = [str(root / "src")]
    if env.get("PYTHONPATH"):
        pythonpath.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    implementation_modules = (
        "agent_assure.onboarding.controls_mutation_config",
        "agent_assure.onboarding.controls_mutation_scaffold",
        "agent_assure.onboarding.controls_mutation_doctor",
    )

    for facade_first in (False, True):
        code = f"""
import importlib

module_names = {implementation_modules!r}
facade_name = "agent_assure.onboarding.controls_mutation"
if {facade_first!r}:
    facade = importlib.import_module(facade_name)
config, scaffold, doctor = tuple(importlib.import_module(name) for name in module_names)
if not {facade_first!r}:
    facade = importlib.import_module(facade_name)

identity_pairs = (
    (config.ControlsMutationOnboardingConfig, facade.ControlsMutationOnboardingConfig),
    (config.ControlsMutationInputBinding, facade.ControlsMutationInputBinding),
    (scaffold.ControlsMutationOnboardingConfig, facade.ControlsMutationOnboardingConfig),
    (scaffold.ScaffoldConflictError, facade.ScaffoldConflictError),
    (scaffold.ScaffoldResult, facade.ScaffoldResult),
    (doctor.ControlsMutationOnboardingConfig, facade.ControlsMutationOnboardingConfig),
    (doctor.DiagnosticStatus, facade.DiagnosticStatus),
    (doctor.DoctorCode, facade.DoctorCode),
    (doctor.DoctorDiagnostic, facade.DoctorDiagnostic),
    (doctor.DoctorReport, facade.DoctorReport),
    (doctor.ScaffoldConflictError, facade.ScaffoldConflictError),
)
assert all(implementation is public for implementation, public in identity_pairs)
"""
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert completed.returncode == 0, completed.stderr + completed.stdout


def test_scaffold_is_complete_idempotent_and_doctor_ready(tmp_path: Path) -> None:
    out = tmp_path / "quickstart"

    created = scaffold_controls_mutation(out)
    first_bytes = {name: (out / name).read_bytes() for name in MANAGED_FILENAMES}
    unchanged = scaffold_controls_mutation(out)
    report = diagnose_controls_mutate(out / CONFIG_FILENAME)

    assert created.status == "created"
    assert unchanged.status == "unchanged"
    assert first_bytes == expected_scaffold_files()
    assert {name: (out / name).read_bytes() for name in MANAGED_FILENAMES} == first_bytes
    assert report.ready is True
    assert report.exit_code == 0
    assert tuple(item.code for item in report.diagnostics) == (
        DoctorCode.CONFIG_PATH,
        DoctorCode.CONFIG_SCHEMA,
        DoctorCode.PACKAGE_VERSION,
        DoctorCode.SUITE_PATH,
        DoctorCode.RUNSET_PATH,
        DoctorCode.THREAT_MANIFEST_PATH,
        DoctorCode.THREAT_MANIFEST_SCHEMA,
        DoctorCode.OUTPUT_PATH,
        DoctorCode.SCHEMA_VERSIONS,
        DoctorCode.INPUT_BINDING,
        DoctorCode.CATALOG_IDENTITY,
        DoctorCode.OPERATOR_CONFIGURATION,
        DoctorCode.THREAT_SCOPE,
        DoctorCode.OPERATOR_APPLICABILITY,
        DoctorCode.OFFLINE_READINESS,
    )
    assert all(item.status is DiagnosticStatus.passed for item in report.diagnostics)
    threat_scope = next(item for item in report.diagnostics if item.code == DoctorCode.THREAT_SCOPE)
    assert "AML.T0067.000" in threat_scope.message
    assert "material-claim-link-regression" in threat_scope.message


def test_init_and_doctor_are_registered_on_main_cli(tmp_path: Path) -> None:
    out = tmp_path / "cli-quickstart"

    first = _RUNNER.invoke(
        app,
        ["init", "controls-mutation", "--out-dir", str(out)],
    )
    second = _RUNNER.invoke(
        app,
        ["init", "controls-mutation", "--out-dir", str(out)],
    )
    doctor = _RUNNER.invoke(
        app,
        ["doctor", "controls-mutate", "--config", str(out / CONFIG_FILENAME)],
    )

    assert first.exit_code == 0, first.output
    assert "scaffold created" in first.output
    assert "run: agent-assure controls mutate" in first.output
    assert second.exit_code == 0, second.output
    assert "scaffold unchanged" in second.output
    assert doctor.exit_code == 0, doctor.output
    assert "controls-mutate doctor: ready" in doctor.output


def test_default_command_signatures_work_without_explicit_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    initialized = _RUNNER.invoke(app, ["init", "controls-mutation"])
    diagnosed = _RUNNER.invoke(app, ["doctor", "controls-mutate"])

    assert initialized.exit_code == 0, initialized.output
    assert diagnosed.exit_code == 0, diagnosed.output
    assert (tmp_path / DEFAULT_SCAFFOLD_DIRECTORY / CONFIG_FILENAME).is_file()


def test_scaffold_resumes_an_exact_partial_generation_transactionally(
    tmp_path: Path,
) -> None:
    expected = expected_scaffold_files()
    out = tmp_path / "partial"
    out.mkdir()
    config = out / CONFIG_FILENAME
    config.write_bytes(expected[CONFIG_FILENAME])

    result = scaffold_controls_mutation(out)

    assert result.status == "created"
    assert config.read_bytes() == expected[CONFIG_FILENAME]
    assert {name: (out / name).read_bytes() for name in MANAGED_FILENAMES} == expected


def test_scaffold_differing_file_is_never_overwritten(tmp_path: Path) -> None:
    out = tmp_path / "conflict"
    out.mkdir()
    config = out / CONFIG_FILENAME
    sentinel = b"user-owned\n"
    config.write_bytes(sentinel)

    with pytest.raises(ScaffoldConflictError, match="conflicting"):
        scaffold_controls_mutation(out)

    assert config.read_bytes() == sentinel
    assert tuple(path.name for path in out.iterdir()) == (CONFIG_FILENAME,)


def test_scaffold_refuses_filesystem_root_without_writing(tmp_path: Path) -> None:
    filesystem_root = Path(tmp_path.anchor)

    with pytest.raises(ScaffoldConflictError, match="filesystem root"):
        scaffold_controls_mutation(filesystem_root)


@pytest.mark.skipif(os.name != "nt", reason="UNC paths are Windows-specific")
def test_scaffold_rejects_explicit_network_path_without_access() -> None:
    network_path = Path(chr(92) * 2 + "invalid-host/share/workflow")

    with pytest.raises(ScaffoldConflictError, match="network filesystem"):
        scaffold_controls_mutation(network_path)


def test_scaffold_rejects_hard_linked_managed_file(tmp_path: Path) -> None:
    expected = expected_scaffold_files()
    out = tmp_path / "hard-link-conflict"
    out.mkdir()
    peer = tmp_path / "peer-config.yaml"
    peer.write_bytes(expected[CONFIG_FILENAME])
    try:
        os.link(peer, out / CONFIG_FILENAME)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(ScaffoldConflictError, match="conflicting"):
        scaffold_controls_mutation(out)

    assert peer.read_bytes() == expected[CONFIG_FILENAME]
    assert tuple(path.name for path in out.iterdir()) == (CONFIG_FILENAME,)


def test_scaffold_rolls_back_files_created_before_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "rollback"
    real_write = controls_mutation_scaffold._write_new_file
    calls = 0

    def fail_second(path: Path, content: bytes) -> controls_mutation_scaffold._CreatedFile:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected write failure")
        return real_write(path, content)

    monkeypatch.setattr(controls_mutation_scaffold, "_write_new_file", fail_second)

    with pytest.raises(OSError, match="injected write failure"):
        scaffold_controls_mutation(out)

    assert not out.exists()


def test_scaffold_rollback_preserves_concurrently_replaced_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "replacement-race"
    real_write = controls_mutation_scaffold._write_new_file
    sentinel = b"concurrent owner\n"
    calls = 0

    def replace_then_fail(
        path: Path,
        content: bytes,
    ) -> controls_mutation_scaffold._CreatedFile:
        nonlocal calls
        calls += 1
        if calls == 1:
            created = real_write(path, content)
            path.unlink()
            path.write_bytes(sentinel)
            return created
        raise OSError("injected write failure after replacement")

    monkeypatch.setattr(controls_mutation_scaffold, "_write_new_file", replace_then_fail)

    with pytest.raises(OSError, match="after replacement"):
        scaffold_controls_mutation(out)

    assert (out / CONFIG_FILENAME).read_bytes() == sentinel


def test_scaffold_removes_partially_written_file_on_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_parent = tmp_path / "created-parent"
    out = created_parent / "fsync-rollback"

    def fail_fsync(descriptor: int) -> None:
        raise OSError(f"injected fsync failure for {descriptor}")

    monkeypatch.setattr(controls_mutation_scaffold.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="injected fsync failure"):
        scaffold_controls_mutation(out)

    assert not out.exists()
    assert not created_parent.exists()


def test_doctor_reports_actionable_missing_config_with_stable_exit(tmp_path: Path) -> None:
    config = tmp_path / "missing" / CONFIG_FILENAME

    result = _RUNNER.invoke(
        app,
        ["doctor", "controls-mutate", "--config", str(config)],
    )

    assert result.exit_code == 2
    assert f"FAIL {DoctorCode.CONFIG_PATH}" in result.output
    assert "agent-assure init controls-mutation" in result.output
    assert f"SKIP {DoctorCode.OFFLINE_READINESS}" in result.output
    assert "exit 2" in result.output


def test_doctor_fails_inapplicable_configured_operator(tmp_path: Path) -> None:
    out = tmp_path / "inapplicable"
    scaffold_controls_mutation(out)
    config_path = out / CONFIG_FILENAME
    config_text = config_path.read_text(encoding="utf-8").replace(
        "drop-material-evidence-link",
        "bypass-required-human-review",
    )
    config_path.write_text(config_text, encoding="utf-8")

    report = diagnose_controls_mutate(config_path)
    applicability = next(
        item for item in report.diagnostics if item.code == DoctorCode.OPERATOR_APPLICABILITY
    )

    assert report.exit_code == 2
    assert applicability.status is DiagnosticStatus.failed
    assert "no static target" in applicability.message
    assert "records both routing and completed review" in applicability.message


def test_doctor_reports_package_version_mismatch(tmp_path: Path) -> None:
    out = tmp_path / "package-mismatch"
    scaffold_controls_mutation(out)
    config_path = out / CONFIG_FILENAME
    config_text = config_path.read_text(encoding="utf-8").replace(
        f'package_version: "{__version__}"',
        'package_version: "999.0.0"',
    )
    config_path.write_text(config_text, encoding="utf-8")

    report = diagnose_controls_mutate(config_path)
    diagnostic = next(
        item for item in report.diagnostics if item.code == DoctorCode.PACKAGE_VERSION
    )

    assert report.exit_code == 2
    assert diagnostic.status is DiagnosticStatus.failed
    assert f"installed {__version__}" in diagnostic.message
    assert diagnostic.action is not None


@pytest.mark.parametrize(
    "error",
    (
        pytest.param(ValueError("injected catalog value failure"), id="value-error"),
        pytest.param(
            CatalogIntegrityError("injected catalog integrity failure"),
            id="integrity-error",
        ),
    ),
)
def test_doctor_reports_core_catalog_identity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    out = tmp_path / "catalog-failure"
    scaffold_controls_mutation(out)

    def fail_catalog(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(controls_mutation_doctor, "build_core_catalog", fail_catalog)

    report = diagnose_controls_mutate(out / CONFIG_FILENAME)
    diagnostic = next(
        item for item in report.diagnostics if item.code == DoctorCode.CATALOG_IDENTITY
    )

    assert report.exit_code == 2
    assert diagnostic.status is DiagnosticStatus.failed
    assert "identity could not be established" in diagnostic.message
    assert "reinstall an intact agent-assure package" in (diagnostic.action or "")
    applicability = next(
        item for item in report.diagnostics if item.code == DoctorCode.OPERATOR_APPLICABILITY
    )
    assert applicability.status is DiagnosticStatus.skipped


def test_doctor_propagates_unexpected_catalog_programming_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "catalog-programming-error"
    scaffold_controls_mutation(out)

    def fail_catalog(*args: object, **kwargs: object) -> None:
        raise RuntimeError("injected programming error")

    monkeypatch.setattr(controls_mutation_doctor, "build_core_catalog", fail_catalog)

    with pytest.raises(RuntimeError, match="injected programming error"):
        diagnose_controls_mutate(out / CONFIG_FILENAME)


def test_doctor_reports_relative_config_path_as_absolute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "relative-config"
    scaffold_controls_mutation(out)
    monkeypatch.chdir(tmp_path)
    relative_config = Path(out.name) / CONFIG_FILENAME

    report = diagnose_controls_mutate(relative_config)
    diagnostic = next(item for item in report.diagnostics if item.code == DoctorCode.CONFIG_PATH)

    assert diagnostic.status is DiagnosticStatus.passed
    assert str(relative_config.absolute()) in diagnostic.message


def test_doctor_rejects_hard_linked_configuration(tmp_path: Path) -> None:
    out = tmp_path / "hard-linked-config"
    scaffold_controls_mutation(out)
    config_path = out / CONFIG_FILENAME
    peer = tmp_path / "peer-config.yaml"
    config_path.replace(peer)
    try:
        os.link(peer, config_path)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    report = diagnose_controls_mutate(config_path)

    assert report.exit_code == 2
    diagnostic = next(item for item in report.diagnostics if item.code == DoctorCode.CONFIG_PATH)
    assert diagnostic.status is DiagnosticStatus.failed
    assert peer.read_bytes() == expected_scaffold_files()[CONFIG_FILENAME]


def test_scaffold_and_doctor_reject_directory_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("owned\n", encoding="utf-8")
    linked_destination = tmp_path / "linked-destination"
    try:
        linked_destination.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory links are unavailable: {exc}")

    with pytest.raises(ScaffoldConflictError, match="regular directory"):
        scaffold_controls_mutation(linked_destination)
    assert sentinel.read_text(encoding="utf-8") == "owned\n"

    out = tmp_path / "doctor-output-link"
    scaffold_controls_mutation(out)
    external_output = tmp_path / "external-output"
    external_output.mkdir()
    (out / "mutation-results").symlink_to(external_output, target_is_directory=True)

    report = diagnose_controls_mutate(out / CONFIG_FILENAME)
    diagnostic = next(item for item in report.diagnostics if item.code == DoctorCode.OUTPUT_PATH)
    assert report.exit_code == 2
    assert diagnostic.status is DiagnosticStatus.failed
    assert "regular directory" in diagnostic.message


def test_confined_directory_errors_do_not_route_by_message_prefix(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()

    for label in ("path", "campaign"):
        with pytest.raises(ValueError) as missing:
            require_confined_input_directory(
                root / "missing",
                root=root,
                label=label,
            )
        assert type(missing.value) is ValueError
        assert str(missing.value) == (f"{label} has a missing or unreadable directory component")

    non_directory = root / "regular-file"
    non_directory.write_text("not a directory\n", encoding="utf-8")
    with pytest.raises(ValueError) as invalid_chain:
        require_confined_input_directory(
            non_directory / "child",
            root=root,
            label="campaign",
        )
    assert type(invalid_chain.value) is ValueError
    assert str(invalid_chain.value) == (
        "campaign contains a symbolic link, junction, or non-directory component"
    )

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="^campaign escapes its allowed root$"):
        require_confined_input_directory(
            outside,
            root=root,
            label="campaign",
        )


def test_doctor_does_not_resolve_targets_for_unbound_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "unbound"
    scaffold_controls_mutation(out)
    runset_path = out / "runset.json"
    payload = json.loads(runset_path.read_text(encoding="utf-8"))
    payload["suite_digest"] = "f" * 64
    runset_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def forbidden(*args: object, **kwargs: object) -> tuple[str, ...]:
        raise AssertionError("applicability requires digest-bound inputs")

    monkeypatch.setattr(
        controls_mutation_doctor,
        "_operator_applicability_errors",
        forbidden,
    )

    report = diagnose_controls_mutate(out / CONFIG_FILENAME)
    binding = next(item for item in report.diagnostics if item.code == DoctorCode.INPUT_BINDING)
    applicability = next(
        item for item in report.diagnostics if item.code == DoctorCode.OPERATOR_APPLICABILITY
    )

    assert binding.status is DiagnosticStatus.failed
    assert applicability.status is DiagnosticStatus.skipped


def test_doctor_never_executes_evaluator_mutation_or_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "static"
    scaffold_controls_mutation(out)
    before = {
        path.relative_to(out).as_posix(): path.read_bytes()
        for path in sorted(out.rglob("*"))
        if path.is_file()
    }

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("execution path must not be called by doctor")

    monkeypatch.setattr(evaluator, "evaluate_runset", forbidden)
    monkeypatch.setattr(execution, "execute_mutation", forbidden)
    monkeypatch.setattr(campaign, "execute_mutation_campaign", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    report = diagnose_controls_mutate(out / CONFIG_FILENAME)

    assert report.ready is True
    assert not (out / "mutation-results").exists()
    after = {
        path.relative_to(out).as_posix(): path.read_bytes()
        for path in sorted(out.rglob("*"))
        if path.is_file()
    }
    assert after == before


def test_doctor_rejects_malformed_threat_manifest(tmp_path: Path) -> None:
    out = tmp_path / "malformed-manifest"
    scaffold_controls_mutation(out)
    manifest = out / "threat-applicability.yaml"
    manifest.write_text("unexpected: field\n", encoding="utf-8")

    report = diagnose_controls_mutate(out / CONFIG_FILENAME)
    diagnostic = next(
        item for item in report.diagnostics if item.code == DoctorCode.THREAT_MANIFEST_SCHEMA
    )
    path_diagnostic = next(
        item for item in report.diagnostics if item.code == DoctorCode.THREAT_MANIFEST_PATH
    )

    assert report.exit_code == 2
    assert path_diagnostic.status is DiagnosticStatus.passed
    assert diagnostic.status is DiagnosticStatus.failed
    assert "exactly the authored or persisted v1 form" in diagnostic.message
    assert not (out / "mutation-results").exists()


def test_doctor_names_unscoped_catalog_threat_references(tmp_path: Path) -> None:
    out = tmp_path / "thin-threat-manifest"
    scaffold_controls_mutation(out)
    manifest_path = out / "threat-applicability.yaml"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace(
            (
                "  - threat_id: material-claim-link-regression\n"
                "    applicability: applicable\n"
                "    critical: false\n"
                "    rationale: The selected operator's project-local regression "
                "reference is in scope.\n"
                "    owner: onboarding-user\n"
                '    reviewed_at: "2026-08-08"\n'
            ),
            "",
        ),
        encoding="utf-8",
        newline="\n",
    )

    report = diagnose_controls_mutate(out / CONFIG_FILENAME)
    diagnostic = next(item for item in report.diagnostics if item.code == DoctorCode.THREAT_SCOPE)

    assert report.exit_code == 2
    assert diagnostic.status is DiagnosticStatus.failed
    assert diagnostic.message == (
        "configured operators have unscoped catalog threat references: "
        "material-claim-link-regression"
    )
    assert "declare each reference" in (diagnostic.action or "")


def test_generated_config_binds_efficacy_and_threat_inputs(tmp_path: Path) -> None:
    out = tmp_path / "config"
    scaffold_controls_mutation(out)

    config = load_controls_mutation_config(out / CONFIG_FILENAME)

    assert config.catalog_id == "core/v1"
    assert config.operator_ids == ("drop-material-evidence-link",)
    assert config.control_efficacy.required_operators == config.operator_ids
    assert config.control_efficacy.surviving_required_operator == "block"
    assert config.control_efficacy.surviving_critical_operator == "block"
    assert config.control_efficacy.surviving_applicable_operator == "review"
    assert config.control_efficacy.critical_threat_uncovered == "review"
    assert config.control_efficacy.applicable_threat_uncovered == "review"
    assert config.control_efficacy.unevaluated_required_operator == "block"
    assert config.control_efficacy.unscoped_catalog_threat_reference == "review"
    assert (out / config.threat_applicability_manifest).is_file()


def test_config_snapshot_hashes_the_parsed_bytes_and_canonicalizes_operator_order(
    tmp_path: Path,
) -> None:
    out = tmp_path / "config-snapshot"
    scaffold_controls_mutation(out)
    config_path = out / CONFIG_FILENAME
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "operator_ids:\n  - drop-material-evidence-link\n",
            ("operator_ids:\n  - drop-material-evidence-link\n  - bypass-required-human-review\n"),
        ),
        encoding="utf-8",
        newline="\n",
    )

    config, contents = load_controls_mutation_config_snapshot(config_path)

    assert contents.sha256 == file_sha256(config_path)
    assert parse_controls_mutation_config(contents.data) == config
    assert config.operator_ids == (
        "bypass-required-human-review",
        "drop-material-evidence-link",
    )


@pytest.mark.parametrize(
    ("path", "message"),
    (
        ("CON", "reserved Windows device"),
        ("nested/con.txt", "reserved Windows device"),
        ("nested/AUX.yaml", "reserved Windows device"),
        ("LPT9/report.json", "reserved Windows device"),
        (f"{'a' * 256}/suite.yaml", "at most 255 characters"),
        ("nested./suite.yaml", "must not end with a dot or space"),
        ("nested /suite.yaml", "portable relative POSIX"),
    ),
)
def test_config_rejects_nonportable_windows_path_components(
    tmp_path: Path,
    path: str,
    message: str,
) -> None:
    out = tmp_path / "portable-paths"
    scaffold_controls_mutation(out)
    config = load_controls_mutation_config(out / CONFIG_FILENAME)
    payload = config.model_dump(mode="json")
    payload["suite_path"] = path

    with pytest.raises(ValueError, match=message):
        ControlsMutationOnboardingConfig.model_validate(payload)


def test_diagnostic_sanitizer_is_shared_and_filters_terminal_controls() -> None:
    error = ValueError("before\x1b[31mRED\x07after\nnext")

    controls_summary = controls_cmd._bounded_error(error)
    init_summary = init_cmd._bounded_error(error)
    onboarding_summary = controls_mutation_doctor._bounded_error(error)

    assert controls_summary == init_summary == onboarding_summary
    assert controls_summary == "before[31mREDafter next"
    assert "\x1b" not in controls_summary
    assert "\x07" not in controls_summary
    assert len(controls_summary) <= 512

    # Removing a Unicode format character must not reassemble a value after
    # the only privacy-detector pass.
    reconstructed_secret = "123-\u202e45-6789"
    assert bounded_error(ValueError(f"bad {reconstructed_secret}")) == "bad [REDACTED]"
    assert display_path(Path(reconstructed_secret)) == "[REDACTED]"


def test_doctor_duplicate_diagnostic_codes_fail_closed(tmp_path: Path) -> None:
    out = tmp_path / "duplicate-code"
    scaffold_controls_mutation(out)
    diagnostic = diagnose_controls_mutate(out / CONFIG_FILENAME).diagnostics[0]

    with pytest.raises(RuntimeError, match="duplicate Doctor diagnostic code"):
        controls_mutation_doctor._ordered_report([diagnostic, diagnostic])
