from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from argparse import Namespace
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.v1_s1_governance as governance  # noqa: E402, I001


@dataclass(frozen=True)
class SigningKey:
    private_key: Path
    public_key: str
    fingerprint: str


def _test_host_tool_identities() -> dict[str, governance.TrustedExecutableIdentity]:
    identities: dict[str, governance.TrustedExecutableIdentity] = {}
    for name in ("git", "ssh-keygen"):
        executable = shutil.which(name)
        if executable is None:
            pytest.skip(f"{name} is unavailable on the Windows integration host")
        path = Path(executable).resolve()
        payload = path.read_bytes()
        identities[name] = governance.TrustedExecutableIdentity(
            path=str(path),
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
    return identities


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout: int = 30,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(arguments),
        cwd=cwd,
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"command failed ({' '.join(arguments)}): {completed.stderr or completed.stdout}"
        )
    return completed


def _run_ssh_keygen(
    arguments: Sequence[str],
    *,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    with governance._isolated_openssh_environment() as environment:
        return _run(arguments, cwd=cwd, env=environment)


def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            governance._trusted_executable("git"),
            "-c",
            "core.longpaths=true",
            "-C",
            str(repository),
            *arguments,
        ],
        cwd=repository,
    )


def _commit_paths(repository: Path, message: str, paths: Sequence[str]) -> str:
    _git(repository, "add", "--", *paths)
    _git(repository, "commit", "--quiet", "--message", message, "--", *paths)
    return _git(repository, "rev-parse", "HEAD^{commit}").stdout.strip()


def _copy_legacy_acceptance_blob(destination_root: Path, relative_path: str) -> None:
    """Copy generation-1 fixture bytes from its immutable accepted closure."""

    destination = destination_root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(
        governance._read_commit_blob(
            ROOT,
            governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
            relative_path,
            owner="generation-1 integration fixture",
        )
    )


def _legacy_record(relative_path: str) -> dict[str, Any]:
    return governance._read_json_from_commit(
        ROOT,
        governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        relative_path,
    )


def _write_synthetic_roadmap(path: Path) -> None:
    """Write a public, minimal roadmap that exercises the frozen S1 contract."""

    accepted_roster = _legacy_record("docs/governance/v1/approval-roster.json")
    defaults = {
        "title": "Synthetic governed ticket",
        "depends_on": [],
        "owner_role": "technical_lead",
        "reviewer_role": "repository_maintainer",
        "stop_conditions": ["Stop if the synthetic governance contract changes."],
        "delivery": {
            "estimate": {
                "scope": "ticket_completion",
                "unit": "focused_engineer_day",
                "p50": 1,
                "p90": 2,
                "confidence": "medium",
                "basis": "Synthetic integration-test prior.",
            },
            "review_effort_p50_days": 0.5,
        },
    }
    tickets = {
        "V1-BOOT-01": {
            "id": "V1-BOOT-01",
            "title": "Synthetic governance bootstrap",
            "dispatch_kind": "kickoff",
        },
        "V1-BASE-01": {
            "id": "V1-BASE-01",
            "title": "Synthetic governed baseline",
            "depends_on": ["V1-BOOT-01"],
            "dispatch_kind": "inventory",
        },
    }
    release_train = {
        "format": "agent-assure-release-train/6",
        "spec_revision": governance.SPEC_REVISION,
        "planning_cadence": {
            "forecast_contract": governance.FORECAST_CONTRACT_ID,
            "forecast_producer_ticket_id": "V1-BASE-01",
            "forecast_producer_work_package_id": "BASE-01F",
            "required_before_sprint": "S2",
            "forecast_must_cover_all_ticket_ids": True,
            "forecast_must_be_current_at_commitment": True,
        },
        "entries": [
            {
                "sprint": "S1",
                "release": "1.0.0a1",
                "maturity": "governed-baseline",
                "artifact_kind": "governance-bundle",
                "ticket_ids": ["V1-BOOT-01", "V1-BASE-01"],
                "authorization_effect": "none",
                "installability": "none",
                "distribution_channels": [],
                "package_version": None,
            }
        ],
    }
    roster_template = {
        "format": "agent-assure-approval-roster/1",
        "spec_revision": governance.SPEC_REVISION,
        "role_assignments": accepted_roster["role_assignments"],
    }

    def block(kind: str, identifier: str, value: Mapping[str, Any]) -> str:
        payload = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
        return (
            f"<!-- handoff:block {kind} {identifier} -->\n"
            f"```json\n{payload}\n```\n"
            "<!-- handoff:end -->\n"
        )

    rendered = [
        "# Synthetic Agent Assure governance roadmap\n\n",
        block("json", "ticket-defaults", defaults),
        block("json", "release-train.json", release_train),
        block("json", "approval-roster", roster_template),
    ]
    rendered.extend(block("ticket", ticket_id, ticket) for ticket_id, ticket in tickets.items())
    path.write_text("\n".join(rendered), encoding="utf-8", newline="\n")


def _canonical_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _generate_signing_key(repository: Path) -> SigningKey:
    ssh_keygen = governance._trusted_executable("ssh-keygen")
    private_key = repository / ".tmp" / "historical-check-signing-key"
    private_key.parent.mkdir(parents=True, exist_ok=True)
    _run_ssh_keygen(
        [
            ssh_keygen,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "agent-assure-historical-check",
            "-f",
            str(private_key),
        ],
        cwd=repository,
    )
    public_parts = Path(f"{private_key}.pub").read_text(encoding="ascii").split()
    public_key = " ".join(public_parts[:2])
    return SigningKey(
        private_key=private_key,
        public_key=public_key,
        fingerprint=governance._public_key_fingerprint(public_key),
    )


def _sign_envelope(
    envelope: Mapping[str, Any],
    *,
    signed_at: str,
    signing_key: SigningKey,
    repository: Path,
    sequence: int,
) -> dict[str, Any]:
    signed = copy.deepcopy(dict(envelope))
    signed["status"] = "signed"
    signed["signed_at_utc"] = signed_at
    signed["signature"] = None
    claim = repository / ".tmp" / f"historical-check-claim-{sequence}.json"
    claim.write_bytes(governance._signature_claim_bytes(signed))
    _run_ssh_keygen(
        [
            governance._trusted_executable("ssh-keygen"),
            "-Y",
            "sign",
            "-f",
            str(signing_key.private_key),
            "-n",
            governance.SIGNATURE_NAMESPACE,
            "-O",
            "hashalg=sha512",
            str(claim),
        ],
        cwd=repository,
    )
    armor = governance._canonical_sshsig_armor(Path(f"{claim}.sig").read_bytes())
    signed["signature"] = base64.b64encode(armor).decode("ascii")
    return signed


def _sign_v2_envelope(
    envelope: Mapping[str, Any],
    *,
    signing_key: SigningKey,
    repository: Path,
    sequence: int,
) -> dict[str, Any]:
    signed = copy.deepcopy(dict(envelope))
    signed["status"] = "signed"
    claim = repository / ".tmp" / f"historical-check-v2-claim-{sequence}.json"
    claim.write_bytes(governance._signature_claim_bytes_v2(signed))
    _run_ssh_keygen(
        [
            governance._trusted_executable("ssh-keygen"),
            "-Y",
            "sign",
            "-f",
            str(signing_key.private_key),
            "-n",
            governance.SIGNATURE_NAMESPACE,
            "-O",
            "hashalg=sha512",
            str(claim),
        ],
        cwd=repository,
    )
    armor = governance._canonical_sshsig_armor(Path(f"{claim}.sig").read_bytes())
    signed["signature"] = base64.b64encode(armor).decode("ascii")
    return signed


def _write_json(repository: Path, relative_path: str, record: Mapping[str, Any]) -> None:
    governance._write_json(repository / relative_path, record)


def _accepted_roster() -> dict[str, Any]:
    roster = _legacy_record("docs/governance/v1/approval-roster.json")
    roster["selection_status"] = "approved"
    roster["limitations"] = [
        limitation
        for limitation in roster["limitations"]
        if limitation
        != "This roster is proposed until the named human signs the scoped kickoff authorizations"
    ]
    return roster


def _confirmed_signing_key(signing_key: SigningKey) -> dict[str, Any]:
    record = _legacy_record("docs/governance/v1/maintainer-signing-key.json")
    record.update(
        {
            "key_status": "confirmed_by_human",
            "public_key": signing_key.public_key,
            "public_key_fingerprint": signing_key.fingerprint,
            "out_of_band_confirmation_evidence": (
                "Ephemeral integration-test key generated and fingerprint-checked in-process."
            ),
        }
    )
    record["limitations"] = [
        limitation
        for limitation in record["limitations"]
        if limitation != "Pending explicit human affirmation of the displayed fingerprint"
    ]
    record["record_digest"] = governance.domain_digest(
        governance.SIGNING_KEY_DOMAIN,
        governance._record_projection(record, "record_digest"),
    )
    return record


def _repository_baseline(repository: Path, *, roadmap_digest: str) -> dict[str, Any]:
    baseline = governance._read_json(repository / "docs/governance/v1/baseline-observations.json")
    runtime = baseline["environment"]["trusted_python_runtime"]
    runtime["site_packages_path"] = str((repository / ".venv/Lib/site-packages").resolve())
    baseline["roadmap"]["raw_digest"] = roadmap_digest
    baseline["observations_digest"] = governance.domain_digest(
        governance.BASELINE_OBSERVATIONS_DOMAIN,
        governance._record_projection(baseline, "observations_digest"),
    )
    return baseline


def _bind_fixture_schemas_to_signing_key(
    repository: Path,
    *,
    signing_key: SigningKey,
) -> None:
    source_fingerprint = str(
        governance._read_json(repository / "docs/governance/v1/maintainer-signing-key.json")[
            "public_key_fingerprint"
        ]
    )
    for schema_path in (repository / "docs/governance/v1").glob("*.schema.json"):
        source = schema_path.read_text(encoding="utf-8")
        rendered = source.replace(source_fingerprint, signing_key.fingerprint)
        if rendered != source:
            schema_path.write_text(rendered, encoding="utf-8", newline="\n")


def _confirmed_ledger(
    snapshot: governance.RoadmapSnapshot,
    baseline: Mapping[str, Any],
    *,
    person_id: str,
    issued_at: str,
) -> dict[str, Any]:
    inventory_completed_at = str(baseline["inventory_completed_at_utc"])
    ledger = governance.build_authoring_ledger(
        snapshot,
        issued_at=issued_at,
        producer_person_id=person_id,
        baseline_observations_digest_value=str(baseline["observations_digest"]),
        inventory_completed_at=inventory_completed_at,
    )
    for row in ledger["rows"]:
        row["row_decision"] = "affirmatively_reconfirmed_after_inventory"
        row["row_confirmed_by_person_id"] = person_id
        row["row_confirmed_at_utc"] = inventory_completed_at
        for proposal in row["execution_proposals"]:
            proposal["decision"] = "affirmatively_reconfirmed_after_inventory"
            proposal["confirmed_by_person_id"] = person_id
            proposal["confirmed_at_utc"] = inventory_completed_at
    ledger["ledger_digest"] = governance._ledger_digest(ledger)
    return ledger


def _live_repository_evidence(closure_commit: str) -> dict[str, Any]:
    return {
        "approved_remote_url": governance.APPROVED_ORIGIN_URL,
        "authoritative_remote_refs": {
            "refs/heads/main": governance.PINNED_BASE_COMMIT,
            "refs/tags/v0.7.0": governance.PINNED_TAG_OBJECT,
            "refs/tags/v0.7.0^{}": governance.PINNED_BASE_COMMIT,
        },
        "branch_name": governance.S1_BRANCH_NAME,
        "fetch_performed": True,
        "head_commit": closure_commit,
        "local_refs": {
            "refs/remotes/origin/main^{commit}": governance.PINNED_BASE_COMMIT,
            "refs/tags/v0.7.0^{tag}": governance.PINNED_TAG_OBJECT,
            "refs/tags/v0.7.0^{commit}": governance.PINNED_BASE_COMMIT,
        },
    }


def _live_repository_evidence_v2(closure_commit: str) -> dict[str, Any]:
    evidence = _live_repository_evidence(closure_commit)
    evidence["branch_name"] = governance.S1_CORRECTIVE_BRANCH_NAME
    return evidence


_SYNTHETIC_FROZEN_RUNTIME_FIELDS = (
    "_FROZEN_PYTHON_ROOT",
    "_FROZEN_PYTHON_EXECUTABLE",
    "_FROZEN_PYTHON_EXECUTABLE_SIZE",
    "_FROZEN_PYTHON_EXECUTABLE_SHA256",
    "_FROZEN_PYTHON_DLL",
    "_FROZEN_PYTHON_DLL_SIZE",
    "_FROZEN_PYTHON_DLL_SHA256",
    "_FROZEN_BASE_RUNTIME_FILE_COUNT",
    "_FROZEN_BASE_RUNTIME_SIZE_BYTES",
    "_FROZEN_BASE_RUNTIME_SHA256",
)


def _install_synthetic_frozen_runtime(
    runtime_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # These files are identity fixtures; no Python process executes them.
    runtime_root.mkdir()
    python_file = runtime_root / "python.exe"
    python_dll = runtime_root / "python312.dll"
    python_file.write_bytes(b"synthetic-frozen-python")
    python_dll.write_bytes(b"synthetic-frozen-python-dll")
    base_count, base_size, base_digest = governance._base_runtime_inventory(runtime_root)
    bindings = {
        "_FROZEN_PYTHON_ROOT": runtime_root,
        "_FROZEN_PYTHON_EXECUTABLE": python_file,
        "_FROZEN_PYTHON_EXECUTABLE_SIZE": python_file.stat().st_size,
        "_FROZEN_PYTHON_EXECUTABLE_SHA256": hashlib.sha256(python_file.read_bytes()).hexdigest(),
        "_FROZEN_PYTHON_DLL": python_dll,
        "_FROZEN_PYTHON_DLL_SIZE": python_dll.stat().st_size,
        "_FROZEN_PYTHON_DLL_SHA256": hashlib.sha256(python_dll.read_bytes()).hexdigest(),
        "_FROZEN_BASE_RUNTIME_FILE_COUNT": base_count,
        "_FROZEN_BASE_RUNTIME_SIZE_BYTES": base_size,
        "_FROZEN_BASE_RUNTIME_SHA256": base_digest,
    }
    assert set(bindings) == set(_SYNTHETIC_FROZEN_RUNTIME_FIELDS)
    for name, value in bindings.items():
        monkeypatch.setattr(governance, name, value)


def _write_synthetic_post_r2_evidence(
    repository: Path,
    *,
    roadmap: Path,
    result_commit: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    _install_synthetic_frozen_runtime(
        (repository.parent / "synthetic-frozen-runtime").resolve(),
        monkeypatch,
    )
    evidence_root = repository / governance.POST_R2_SUITE_EVIDENCE_DIRECTORY
    evidence_root.mkdir(parents=True)
    stdout = (
        b"....                                                                     [100%]\n"
        b"4 passed, 1 skipped, 1 xfailed in 1.25s\n"
    )
    stderr = b""
    (evidence_root / "pytest.stdout.bin").write_bytes(stdout)
    (evidence_root / "pytest.stderr.bin").write_bytes(stderr)

    (repository / ".venv").mkdir(parents=True)
    (repository / ".venv/pyvenv.cfg").write_bytes(b"home = synthetic-base\n")
    site_packages = repository / ".venv/Lib/site-packages/pytest"
    site_packages.mkdir(parents=True)
    (site_packages / "__init__.py").write_bytes(b"# synthetic pytest runtime\n")
    test_runtime = {
        "format": "agent-assure-s1-post-r2-test-runtime/2",
        "pyvenv_configuration": governance._post_r2_runtime_file_evidence(
            repository,
            repository / ".venv/pyvenv.cfg",
            owner="synthetic post-R2 pyvenv configuration",
        ),
        "site_packages_inventory": {
            "format": "agent-assure-s1-post-r2-test-runtime-inventory/1",
            "relative_root": ".venv/Lib/site-packages",
            "exclusion_policy": {
                "directory_names": ["__pycache__"],
                "forbidden_direct_file_suffixes": [".pyc", ".pyo"],
                "reason": "cache_directories_inert_under_fresh_pycache_prefix",
            },
            "file_count": governance.POST_R2_TEST_RUNTIME_FILE_COUNT,
            "size_bytes": governance.POST_R2_TEST_RUNTIME_SIZE_BYTES,
            "sha256": "sha256:" + governance.POST_R2_TEST_RUNTIME_SHA256,
        },
        "base_runtime": {
            "root": str(governance._FROZEN_PYTHON_ROOT),
            "python_executable": {
                "absolute_path": str(governance._FROZEN_PYTHON_EXECUTABLE),
                "size_bytes": governance._FROZEN_PYTHON_EXECUTABLE_SIZE,
                "sha256": "sha256:" + governance._FROZEN_PYTHON_EXECUTABLE_SHA256,
            },
            "python_dll": {
                "absolute_path": str(governance._FROZEN_PYTHON_DLL),
                "size_bytes": governance._FROZEN_PYTHON_DLL_SIZE,
                "sha256": "sha256:" + governance._FROZEN_PYTHON_DLL_SHA256,
            },
            "inventory": {
                "file_count": governance._FROZEN_BASE_RUNTIME_FILE_COUNT,
                "size_bytes": governance._FROZEN_BASE_RUNTIME_SIZE_BYTES,
                "sha256": "sha256:" + governance._FROZEN_BASE_RUNTIME_SHA256,
            },
        },
    }
    test_surface = {
        "format": "agent-assure-s1-post-r2-test-surface/1",
        "subject_result_commit": result_commit,
        "directory_roots": list(governance.POST_R2_TEST_AFFECTING_DIRECTORIES),
        "tracked_root_files": list(governance.POST_R2_TRACKED_ROOT_FILES),
        "root_config_paths": list(governance.POST_R2_ROOT_TEST_CONFIG_PATHS),
        "cache_policy": {
            "excluded_directory_name": "__pycache__",
            "reason": "fresh_absolute_pycache_prefix_makes_source_adjacent_caches_inert",
            "forbidden_direct_file_suffixes": [".pyc", ".pyo"],
        },
        "local_exclude": {
            "path": ".git/info/exclude",
            "size_bytes": governance.POST_R2_GIT_EXCLUDE_SIZE_BYTES,
            "sha256": "sha256:" + governance.POST_R2_GIT_EXCLUDE_SHA256,
        },
        "file_count": 1,
        "size_bytes": 1,
        "sha256": governance.raw_digest(b"synthetic post-R2 test surface"),
    }
    monkeypatch.setattr(
        governance,
        "_post_r2_test_runtime_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(test_runtime),
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_test_surface_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(test_surface),
    )
    governance_sources = governance._post_r2_governance_source_evidence(
        repository,
        roadmap,
    )
    process_temp_root = (repository.parent / "external-process-temp-root").resolve()
    process_temp_root.mkdir()
    monkeypatch.setattr(governance, "POST_R2_PROCESS_TEMP_ROOT", process_temp_root)
    process_temp = (
        process_temp_root / f"{governance.POST_R2_PROCESS_TEMP_PREFIX}synthetic"
    ).resolve()
    basetemp = process_temp / governance.POST_R2_PYTEST_BASETEMP_DIRECTORY
    repository_state = {
        "head_commit": result_commit,
        "clean": True,
        "status_command": ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        "status_stdout_size_bytes": 0,
        "status_stdout_sha256": governance.raw_digest(b""),
    }
    projection: dict[str, Any] = {
        "format": "agent-assure-s1-post-r2-suite-evidence/3",
        "acceptance_generation": 2,
        "subject_result_parent_commit": governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "subject_result_commit": result_commit,
        "corrective_authorization_claim_digest": (governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST),
        "governance_sources": governance_sources,
        "repository_test_surface": test_surface,
        "command": {
            "argv": governance._post_r2_pytest_argv(
                repository,
                basetemp=basetemp,
                process_temp=process_temp,
                test_surface=test_surface,
            ),
            "working_directory": str(repository.resolve()),
            "environment": governance._post_r2_subprocess_environment(
                repository,
                basetemp,
                process_temp=process_temp,
                legacy_v3_policy=True,
            ),
            "python_executable": test_runtime["base_runtime"]["python_executable"],
            "descendant_runtime": governance._post_r2_descendant_runtime_record(
                repository,
                basetemp=basetemp,
                process_temp=process_temp,
                legacy_v3_policy=True,
            ),
            "bootstrap_input": governance._post_r2_bootstrap_input(
                repository,
                basetemp=basetemp,
                process_temp=process_temp,
                legacy_v3_policy=True,
            )[1],
            "bytecode_policy": governance._post_r2_bytecode_policy(
                basetemp,
                legacy_v3_policy=True,
            ),
            "test_runtime": test_runtime,
        },
        "time_evidence": {
            **governance.ATTESTATION_V2_TIME_EVIDENCE,
            "started_at_utc": "2026-10-15T20:26:00Z",
            "completed_at_utc": "2026-10-15T20:27:00Z",
        },
        "repository_precondition": repository_state,
        "repository_postcondition": copy.deepcopy(repository_state),
        "execution": {
            "exit_code": 0,
            "outcome": "passed",
            "pytest_totals": {
                "collected": 6,
                "passed": 4,
                "failed": 0,
                "skipped": 1,
                "xfailed": 1,
                "xpassed": 0,
                "errors": 0,
            },
            "stdout": {
                "file_name": "pytest.stdout.bin",
                "size_bytes": len(stdout),
                "sha256": governance.raw_digest(stdout),
            },
            "stderr": {
                "file_name": "pytest.stderr.bin",
                "size_bytes": len(stderr),
                "sha256": governance.raw_digest(stderr),
            },
        },
    }
    record = {
        **projection,
        "evidence_digest": governance.domain_digest(
            governance.POST_R2_SUITE_EVIDENCE_DOMAIN,
            projection,
        ),
    }
    evidence_path = evidence_root / "post-r2-suite-evidence.json"
    governance._write_json(evidence_path, record)
    governance.validate_post_r2_suite_evidence_source(
        evidence_path,
        expected_result_commit=result_commit,
        expected_repository_root=repository,
        require_passed=True,
    )
    return evidence_path


def _load_governance_from_clone(repository: Path) -> Any:
    module_name = f"synthetic_v2_governance_{hash(repository)}"
    spec = importlib.util.spec_from_file_location(
        module_name,
        repository / "scripts/v1_s1_governance.py",
    )
    if spec is None or spec.loader is None:
        pytest.fail("unable to load the standalone generation-2 validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(os.name != "nt", reason="the governed S1 toolchain is Windows-host-bound")
def test_historical_check_validates_the_full_signed_closure_after_a_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        governance,
        "TRUSTED_EXECUTABLE_IDENTITIES",
        _test_host_tool_identities(),
    )
    repository = tmp_path / "repository"
    _run(
        [
            governance._trusted_executable("git"),
            "-c",
            "core.longpaths=true",
            "clone",
            "--quiet",
            "--no-local",
            "--no-checkout",
            str(ROOT),
            str(repository),
        ],
        cwd=tmp_path,
        timeout=60,
    )
    _git(
        repository,
        "checkout",
        "--quiet",
        "-B",
        governance.S1_BRANCH_NAME,
        governance.PINNED_BASE_COMMIT,
    )
    _git(repository, "config", "user.name", "Agent Assure Historical Check")
    _git(repository, "config", "user.email", "historical-check@example.invalid")
    _git(repository, "remote", "set-url", "origin", governance.APPROVED_ORIGIN_URL)

    exclude = repository / ".git/info/exclude"
    with exclude.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\nAgent_Assure_Implementation_Roadmap.md\n.tmp/\n")
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    _write_synthetic_roadmap(roadmap)

    for relative_path, kind in governance._bundle_inventory_paths():
        if kind != "completion_receipt":
            _copy_legacy_acceptance_blob(repository, relative_path)

    signing_key = _generate_signing_key(repository)
    _bind_fixture_schemas_to_signing_key(repository, signing_key=signing_key)
    monkeypatch.setattr(governance, "MAINTAINER_PUBLIC_KEY", signing_key.public_key)
    monkeypatch.setattr(
        governance,
        "MAINTAINER_KEY_FINGERPRINT",
        signing_key.fingerprint,
    )

    snapshot = governance.load_roadmap(roadmap)
    baseline = _repository_baseline(repository, roadmap_digest=snapshot.raw_digest)
    inventory_time = governance._parse_utc(
        str(baseline["inventory_completed_at_utc"]),
        owner="test baseline inventory",
    )
    ledger_issued = _canonical_utc(inventory_time + timedelta(minutes=1))
    record_issued = _canonical_utc(inventory_time + timedelta(minutes=2))
    valid_until = _canonical_utc(inventory_time + timedelta(days=30))
    kickoff_signed = _canonical_utc(inventory_time + timedelta(minutes=3))
    forecast_signed = _canonical_utc(inventory_time + timedelta(minutes=4))
    forecast_accepted = _canonical_utc(inventory_time + timedelta(minutes=5))
    base_completed = _canonical_utc(inventory_time + timedelta(minutes=6))
    boot_completed = _canonical_utc(inventory_time + timedelta(minutes=7))
    bundle_signed = _canonical_utc(inventory_time + timedelta(minutes=8))
    gate_checked = _canonical_utc(inventory_time + timedelta(minutes=9))
    attestation_signed = _canonical_utc(inventory_time + timedelta(minutes=10))

    roster = _accepted_roster()
    person_id = str(roster["maintainer_person_id"])
    roster_digest = governance.approval_roster_digest(roster)
    key_record = _confirmed_signing_key(signing_key)
    ledger = _confirmed_ledger(
        snapshot,
        baseline,
        person_id=person_id,
        issued_at=ledger_issued,
    )
    registry = governance._read_json(
        repository / "docs/governance/v1/delivery-forecast.aggregation-registry.json"
    )
    kickoffs: dict[str, dict[str, Any]] = {}
    for sequence, ticket_id in enumerate(("V1-BASE-01", "V1-BOOT-01"), start=1):
        kickoff = governance.build_kickoff_authorization(
            snapshot,
            ticket_id=ticket_id,
            roster_digest=roster_digest,
            person_id=person_id,
            issued_at=record_issued,
            valid_until=valid_until,
            status="authorized",
        )
        kickoff["signature_envelope"] = _sign_envelope(
            kickoff["signature_envelope"],
            signed_at=kickoff_signed,
            signing_key=signing_key,
            repository=repository,
            sequence=sequence,
        )
        kickoffs[ticket_id] = kickoff

    forecast = governance.build_forecast(
        snapshot,
        ledger,
        registry,
        issued_at=record_issued,
        valid_until=valid_until,
        producer_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        requested_status="accepted",
    )
    forecast["signature_envelope"] = _sign_envelope(
        forecast["signature_envelope"],
        signed_at=forecast_signed,
        signing_key=signing_key,
        repository=repository,
        sequence=3,
    )
    forecast_receipt = forecast["acceptance_receipt"]
    forecast_receipt["signature_envelope"] = _sign_envelope(
        forecast_receipt["signature_envelope"],
        signed_at=forecast_accepted,
        signing_key=signing_key,
        repository=repository,
        sequence=4,
    )

    governed_records: dict[str, Mapping[str, Any]] = {
        "docs/governance/v1/approval-roster.json": roster,
        "docs/governance/v1/baseline-observations.json": baseline,
        "docs/governance/v1/delivery-forecast.authoring-ledger.json": ledger,
        "docs/governance/v1/delivery-forecast.json": forecast,
        "docs/governance/v1/kickoff-authorization-v1-base-01.json": kickoffs["V1-BASE-01"],
        "docs/governance/v1/kickoff-authorization-v1-boot-01.json": kickoffs["V1-BOOT-01"],
        "docs/governance/v1/maintainer-signing-key.json": key_record,
    }
    for relative_path, record in governed_records.items():
        _write_json(repository, relative_path, record)

    result_paths = [
        path for path, kind in governance._bundle_inventory_paths() if kind != "completion_receipt"
    ]
    result_commit = _commit_paths(repository, "S1 reviewed result", result_paths)
    assert (
        _git(repository, "rev-parse", f"{result_commit}^").stdout.strip()
        == governance.PINNED_BASE_COMMIT
    )
    nonreceipt_inventory = governance._result_artifact_inventory(repository, result_commit)
    result_evidence = {str(item["path"]): item for item in nonreceipt_inventory}

    receipts: dict[str, dict[str, Any]] = {}
    for sequence, (ticket_id, signed_at) in enumerate(
        (("V1-BASE-01", base_completed), ("V1-BOOT-01", boot_completed)),
        start=5,
    ):
        report_path = f"docs/governance/v1/completion-report-{ticket_id.lower()}.md"
        evidence = [result_evidence[report_path]] + [
            result_evidence[path] for path, _kind in governance._completion_review_paths(ticket_id)
        ]
        receipt = governance.build_ticket_completion_receipt(
            snapshot,
            repository_root=repository,
            ticket_id=ticket_id,
            roster_digest=roster_digest,
            kickoff_authorization_digest=str(kickoffs[ticket_id]["authorization_digest"]),
            person_id=person_id,
            base_commit=governance.PINNED_BASE_COMMIT,
            result_commit=result_commit,
            issued_at=record_issued,
            valid_until=valid_until,
            status="accepted_for_development",
            artifact_evidence_override=evidence,
        )
        receipt["signature_envelope"] = _sign_envelope(
            receipt["signature_envelope"],
            signed_at=signed_at,
            signing_key=signing_key,
            repository=repository,
            sequence=sequence,
        )
        receipts[ticket_id] = receipt
        _write_json(
            repository,
            f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json",
            receipt,
        )

    inventory = list(nonreceipt_inventory)
    inventory.extend(
        governance._artifact_evidence(repository, path, kind=kind)
        for path, kind in governance._bundle_inventory_paths()
        if kind == "completion_receipt"
    )
    bundle = governance.build_governance_bundle(
        snapshot,
        repository_root=repository,
        roster=roster,
        kickoff_records=kickoffs,
        completion_receipts=receipts,
        forecast=forecast,
        signing_key=key_record,
        baseline_observations=baseline,
        person_id=person_id,
        base_commit=governance.PINNED_BASE_COMMIT,
        issued_at=record_issued,
        valid_until=valid_until,
        status="accepted_for_development",
        artifact_inventory_override=inventory,
    )
    bundle["signature_envelope"] = _sign_envelope(
        bundle["signature_envelope"],
        signed_at=bundle_signed,
        signing_key=signing_key,
        repository=repository,
        sequence=7,
    )
    bundle_path = "docs/governance/v1/governance-bundle.json"
    _write_json(repository, bundle_path, bundle)

    closure_paths = [
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
        bundle_path,
    ]
    closure_commit = _commit_paths(repository, "S1 accepted closure", closure_paths)
    assert _git(repository, "rev-parse", f"{closure_commit}^").stdout.strip() == result_commit

    attestation = governance.build_current_acceptance_attestation(
        snapshot,
        repository_root=repository,
        bundle=bundle,
        live_repository_evidence=_live_repository_evidence(closure_commit),
        gate_checked_at=gate_checked,
        signature_requested_at=attestation_signed,
        signer_person_id=person_id,
    )
    attestation["signature_envelope"] = _sign_envelope(
        attestation["signature_envelope"],
        signed_at=attestation_signed,
        signing_key=signing_key,
        repository=repository,
        sequence=8,
    )
    tag_message = repository / ".tmp" / "historical-check-attestation.json"
    tag_message.write_bytes(governance._render_acceptance_attestation_bytes(attestation))
    _git(
        repository,
        "-c",
        "tag.gpgSign=false",
        "tag",
        "--force",
        "--annotate",
        "--cleanup=verbatim",
        f"--file={tag_message}",
        governance.S1_ACCEPTANCE_TAG_NAME,
        closure_commit,
    )
    tag_object = _git(
        repository,
        "rev-parse",
        f"refs/tags/{governance.S1_ACCEPTANCE_TAG_NAME}^{{tag}}",
    ).stdout.strip()

    later = repository / "later-sprint.txt"
    later.write_text("later sprint descendant\n", encoding="utf-8", newline="\n")
    later_commit = _commit_paths(repository, "later sprint", [later.name])
    assert later_commit not in {result_commit, closure_commit}
    (repository / "docs/governance/v1/delivery-forecast.json").write_text(
        '{"working_tree":"deliberately invalid"}\n',
        encoding="utf-8",
        newline="\n",
    )

    assert (
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(repository / "docs/governance/v1"),
                roadmap=str(roadmap),
                allow_pending=False,
                accept_now=False,
                historical=True,
                closure_commit=closure_commit,
                acceptance_tag_object=tag_object,
                fetch_authoritative_refs=False,
                commitment_time=None,
                attestation_plan_dir=None,
                attestation_signed_at=None,
            )
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert output == {
        "acceptance_tag_object": tag_object,
        "bundle_digest": bundle["bundle_digest"],
        "bundle_status": "accepted_for_development",
        "forecast_status": "accepted",
        "record_digest": forecast["record_digest"],
        "result": "valid_historical_accepted",
        "signatures": "all_required_verified",
    }


@pytest.mark.skipif(os.name != "nt", reason="the governed S1 toolchain is Windows-host-bound")
def test_generation_2_topology_tag_and_self_binding_in_standalone_clone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise synthetic v2 topology, SSHSIG, tag, and self-binding on Windows.

    Focused unit tests cover the record validators. This integration deliberately
    substitutes synthetic roadmap/record validators and therefore does not claim
    accepted-configuration or full generation-2 end-to-end proof.
    """

    trusted_tools = _test_host_tool_identities()
    monkeypatch.setattr(governance, "TRUSTED_EXECUTABLE_IDENTITIES", trusted_tools)
    repository = tmp_path / "repository"
    _run(
        [
            governance._trusted_executable("git"),
            "-c",
            "core.longpaths=true",
            "clone",
            "--quiet",
            "--no-local",
            "--no-checkout",
            str(ROOT),
            str(repository),
        ],
        cwd=tmp_path,
        timeout=60,
    )
    _git(
        repository,
        "checkout",
        "--quiet",
        "-B",
        governance.S1_CORRECTIVE_BRANCH_NAME,
        governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
    )
    _git(repository, "config", "user.name", "Agent Assure Generation 2 Check")
    _git(repository, "config", "user.email", "generation-2-check@example.invalid")
    _git(repository, "remote", "set-url", "origin", governance.APPROVED_ORIGIN_URL)

    exclude = repository / ".git/info/exclude"
    with exclude.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\nAgent_Assure_Implementation_Roadmap.md\n.tmp/\n.venv/\n")
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    _write_synthetic_roadmap(roadmap)
    snapshot = governance.load_roadmap(roadmap)
    signing_key = _generate_signing_key(repository)
    monkeypatch.setattr(governance, "MAINTAINER_PUBLIC_KEY", signing_key.public_key)
    monkeypatch.setattr(
        governance,
        "MAINTAINER_KEY_FINGERPRINT",
        signing_key.fingerprint,
    )

    result_paths = {
        path
        for ticket_id in ("V1-BASE-01", "V1-BOOT-01")
        for path, _kind in governance._completion_review_paths_v2(ticket_id)
    }
    result_paths.update(
        {
            "docs/governance/v1/completion-report-v1-base-01.md",
            "docs/governance/v1/completion-report-v1-boot-01.md",
        }
    )
    for relative in sorted(result_paths):
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = ROOT / relative
        if source.is_file():
            shutil.copyfile(source, destination)
        else:
            destination.write_text(
                f"synthetic generation-2 reviewed artifact: {relative}\n",
                encoding="utf-8",
                newline="\n",
            )

    allowed_paths = sorted(
        result_paths | governance.S1_CORRECTIVE_CLOSURE_PATHS,
        key=governance._utf8_sort_key,
    )
    authorization = {
        "format": "agent-assure-s1-corrective-kickoff-authorization/1",
        "authorization_status": "authorized",
        "signed_claim_artifact": {
            "sha256": governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        },
        "signed_claim": {
            "authorization_kind": "prospective_corrective_implementation",
            "authorization_effect": "corrective_s1_development_governance_only",
            "authorized_person_id": "acblabs",
            "authorized_role": "repository_maintainer",
            "tracked_allowed_paths": allowed_paths,
        },
        "import_verification": {
            "verification_recorded_at_utc": "2026-10-15T20:17:00.0000000Z",
        },
    }
    baseline = {
        "inventory_started_at_utc": "2026-10-15T20:18:00.0000000Z",
        "observations_digest": governance.raw_digest(b"synthetic-v2-baseline"),
    }
    issued_at = "2026-10-15T20:20:00Z"
    valid_until = "2026-10-16T20:20:00Z"
    forecast_import_evidence = governance._forecast_v2_signature_import_evidence(
        signature_plan_digest=governance.raw_digest(b"synthetic-v2-forecast-plan"),
        claim_preparation_started_at_utc="2026-10-15T20:21:00Z",
        import_verification_started_at_utc="2026-10-15T20:22:00Z",
        import_verification_completed_at_utc="2026-10-15T20:23:00Z",
        issued_at_utc=issued_at,
        valid_until_utc=valid_until,
    )
    forecast = {
        "format": "agent-assure-delivery-forecast/2",
        "forecast_status": "accepted",
        "human_review_status": "complete",
        "issued_at_utc": issued_at,
        "valid_until_utc": valid_until,
        "record_digest": governance.raw_digest(b"synthetic-v2-forecast"),
        "estimation_catalog_digest": governance.raw_digest(b"synthetic-v2-catalog"),
        "aggregation_method_registry_digest": governance.raw_digest(b"synthetic-v2-registry"),
        "authoring_ledger_digest": governance.raw_digest(b"synthetic-v2-ledger"),
        "signature_envelope": {
            "status": "signed",
            "verification_evidence": forecast_import_evidence,
        },
        "acceptance_receipt": {
            "receipt_status": "accepted_for_development",
            "receipt_digest": governance.raw_digest(b"synthetic-v2-forecast-receipt"),
            "signature_envelope": {
                "status": "signed",
                "verification_evidence": forecast_import_evidence,
            },
        },
    }
    synthetic_records: dict[str, Mapping[str, Any]] = {
        "docs/governance/v1/baseline-observations.json": baseline,
        "docs/governance/v1/corrective-kickoff-authorization.json": authorization,
        "docs/governance/v1/delivery-forecast.estimation-catalog.json": {
            "format": "agent-assure-delivery-forecast-estimation-catalog/2"
        },
        "docs/governance/v1/delivery-forecast.aggregation-registry.json": {
            "format": "agent-assure-delivery-forecast-aggregation-registry/2"
        },
        "docs/governance/v1/delivery-forecast.authoring-ledger.json": {
            "format": "agent-assure-delivery-forecast-authoring-ledger/2"
        },
        "docs/governance/v1/delivery-forecast.json": forecast,
    }
    for relative, record in synthetic_records.items():
        _write_json(repository, relative, record)
    source_fingerprint = str(
        governance._read_json(repository / "docs/governance/v1/maintainer-signing-key.json")[
            "public_key_fingerprint"
        ]
    )
    for relative in sorted(path for path in result_paths if path.endswith(".schema.json")):
        schema_path = repository / relative
        source = schema_path.read_text(encoding="utf-8")
        if relative.endswith("current-acceptance-attestation.schema.json"):
            schema_record = json.loads(source)
            bound_roadmap_digest = schema_record["properties"]["full_roadmap_digest"]["const"]
            source = source.replace(bound_roadmap_digest, snapshot.raw_digest)
        schema_path.write_text(
            source.replace(source_fingerprint, signing_key.fingerprint),
            encoding="utf-8",
            newline="\n",
        )
    _git(repository, "add", "--intent-to-add", "--", *sorted(result_paths))

    changed = set(
        _git(
            repository,
            "diff",
            "--name-only",
            governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        ).stdout.splitlines()
    )
    for relative in sorted(result_paths - changed):
        path = repository / relative
        if relative.endswith(".json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            record["$comment"] = "synthetic generation-2 historical integration fixture"
            governance._write_json(path, record)
        else:
            with path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write("\n# synthetic generation-2 historical integration fixture\n")
    changed = set(
        _git(
            repository,
            "diff",
            "--name-only",
            governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        ).stdout.splitlines()
    )
    assert changed == result_paths
    result_commit = _commit_paths(
        repository,
        "S1 corrective generation-2 result",
        sorted(result_paths),
    )
    assert (
        _git(repository, "rev-parse", f"{result_commit}^").stdout.strip()
        == governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT
    )

    roster = governance._read_json(repository / "docs/governance/v1/approval-roster.json")
    person_id = str(roster["maintainer_person_id"])
    roster_digest = governance.approval_roster_digest(roster)
    predecessor_binding = {
        "acceptance_generation": 1,
        "disposition": "superseded_nonconforming",
        "noncurrent_reason": "forecast_and_governance_provenance_nonconformance",
        "tag_name": governance.S1_ACCEPTANCE_TAG_NAME,
        "tag_object": governance.S1_ACCEPTANCE_V1_TAG_OBJECT,
        "baseline_commit": governance.PINNED_BASE_COMMIT,
        "result_commit": governance.S1_ACCEPTANCE_V1_RESULT_COMMIT,
        "closure_commit": governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "bundle_digest": governance.S1_ACCEPTANCE_V1_BUNDLE_DIGEST,
        "forecast_digest": governance.S1_ACCEPTANCE_V1_FORECAST_DIGEST,
        "objects_remain_immutable": True,
    }
    monkeypatch.setattr(
        governance,
        "_load_corrective_authorization_from_result",
        lambda *_args, **_kwargs: authorization,
    )
    monkeypatch.setattr(
        governance,
        "_generation_1_supersession_binding",
        lambda *_args, **_kwargs: predecessor_binding,
    )
    # Force this fixture to work when the production laptop path is unavailable.
    absent_python = tmp_path / "absent-production-runtime" / "python.exe"
    assert not absent_python.exists()
    monkeypatch.setattr(governance, "_FROZEN_PYTHON_EXECUTABLE", absent_python)
    post_r2_evidence = _write_synthetic_post_r2_evidence(
        repository,
        roadmap=roadmap,
        result_commit=result_commit,
        monkeypatch=monkeypatch,
    )
    fixture_python = governance._FROZEN_PYTHON_EXECUTABLE
    assert fixture_python != absent_python
    assert fixture_python.parent == (repository.parent / "synthetic-frozen-runtime").resolve()
    fixture_python_bytes = fixture_python.read_bytes()
    try:
        fixture_python.unlink()
        with pytest.raises(
            governance.GovernanceError, match="executable source is not a regular file"
        ):
            governance.validate_post_r2_suite_evidence_source(
                post_r2_evidence,
                expected_result_commit=result_commit,
                expected_repository_root=repository,
                require_passed=True,
            )
        fixture_python.write_bytes(bytes(byte ^ 1 for byte in fixture_python_bytes))
        with pytest.raises(governance.GovernanceError, match="executable source bytes changed"):
            governance.validate_post_r2_suite_evidence_source(
                post_r2_evidence,
                expected_result_commit=result_commit,
                expected_repository_root=repository,
                require_passed=True,
            )
    finally:
        fixture_python.write_bytes(fixture_python_bytes)

    receipts: dict[str, dict[str, Any]] = {}
    receipt_times = {
        "V1-BASE-01": ("2026-10-15T20:30:00Z", "2026-10-15T20:31:00Z", 1),
        "V1-BOOT-01": ("2026-10-15T20:30:30Z", "2026-10-15T20:32:00Z", 2),
    }
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        prepared_at, imported_at, sequence = receipt_times[ticket_id]
        monkeypatch.setattr(
            governance,
            "_canonical_host_utc_now",
            lambda observed=prepared_at: observed,
        )
        receipt = governance.build_ticket_completion_receipt_v2(
            snapshot,
            repository_root=repository,
            ticket_id=ticket_id,
            roster_digest=roster_digest,
            person_id=person_id,
            result_commit=result_commit,
            post_r2_suite_evidence_path=(post_r2_evidence if ticket_id == "V1-BOOT-01" else None),
            status="accepted_for_development",
        )
        receipt["signature_envelope"] = _sign_v2_envelope(
            receipt["signature_envelope"],
            signing_key=signing_key,
            repository=repository,
            sequence=sequence,
        )
        monkeypatch.setattr(
            governance,
            "_canonical_host_utc_now",
            lambda observed=imported_at: observed,
        )
        receipts[ticket_id] = governance.record_v2_signature_import_observation(receipt)

    monkeypatch.setattr(
        governance,
        "_canonical_host_utc_now",
        lambda: "2026-10-15T20:35:00Z",
    )
    bundle = governance.build_governance_bundle_v2(
        snapshot,
        repository_root=repository,
        roster=roster,
        completion_receipts=receipts,
        forecast=forecast,
        baseline_observations=baseline,
        person_id=person_id,
        result_commit=result_commit,
        issued_at=issued_at,
        valid_until=valid_until,
        status="accepted_for_development",
    )
    bundle["signature_envelope"] = _sign_v2_envelope(
        bundle["signature_envelope"],
        signing_key=signing_key,
        repository=repository,
        sequence=3,
    )
    monkeypatch.setattr(
        governance,
        "_canonical_host_utc_now",
        lambda: "2026-10-15T20:36:00Z",
    )
    bundle = governance.record_v2_signature_import_observation(bundle)

    completion_schema = governance._read_json(
        repository / "docs/governance/v1/ticket-completion-receipt.schema.json"
    )
    for ticket_id, receipt in receipts.items():
        governance._validate_json_schema(
            receipt,
            completion_schema,
            owner=f"{ticket_id} integration corrective receipt",
        )
        _write_json(
            repository,
            f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json",
            receipt,
        )
    governance._validate_json_schema(
        bundle,
        governance._read_json(repository / "docs/governance/v1/governance-bundle.schema.json"),
        owner="integration corrective governance bundle",
    )
    _write_json(repository, "docs/governance/v1/governance-bundle.json", bundle)
    closure_paths = sorted(governance.S1_CORRECTIVE_CLOSURE_PATHS)
    closure_commit = _commit_paths(
        repository,
        "S1 corrective generation-2 closure",
        closure_paths,
    )
    assert _git(repository, "rev-parse", f"{closure_commit}^").stdout.strip() == result_commit
    assert (
        set(
            _git(
                repository, "diff", "--name-only", result_commit, closure_commit
            ).stdout.splitlines()
        )
        == governance.S1_CORRECTIVE_CLOSURE_PATHS
    )

    attestation = governance.build_current_acceptance_attestation_v2(
        snapshot,
        repository_root=repository,
        bundle=bundle,
        live_repository_evidence=_live_repository_evidence_v2(closure_commit),
        validation_started_at="2026-10-15T20:40:00Z",
        gate_completed_at="2026-10-15T20:41:00Z",
        attestation_preparation_started_at="2026-10-15T20:42:00Z",
        signer_person_id=person_id,
    )
    attestation["signature_envelope"] = _sign_v2_envelope(
        attestation["signature_envelope"],
        signing_key=signing_key,
        repository=repository,
        sequence=4,
    )
    governance._validate_json_schema(
        attestation,
        governance._read_json(
            repository / "docs/governance/v1/current-acceptance-attestation.schema.json"
        ),
        owner="integration generation-2 current acceptance attestation",
    )
    tag_message = repository / ".tmp/generation-2-acceptance-attestation.json"
    tag_message.write_bytes(governance._render_acceptance_attestation_bytes(attestation))
    _git(
        repository,
        "-c",
        "tag.gpgSign=false",
        "tag",
        "--force",
        "--annotate",
        "--cleanup=verbatim",
        f"--file={tag_message}",
        governance.S1_ACCEPTANCE_V2_TAG_NAME,
        closure_commit,
    )
    tag_object = _git(
        repository,
        "rev-parse",
        f"refs/tags/{governance.S1_ACCEPTANCE_V2_TAG_NAME}^{{tag}}",
    ).stdout.strip()

    standalone = _load_governance_from_clone(repository)
    standalone_historical = standalone._parser().parse_args(
        [
            "successor-v3-historical-check",
            "--expected-c3",
            "1" * 40,
            "--expected-a3",
            "2" * 40,
            "--output",
            r"C:\tmp\agent-assure-s1-v3-node-execution-test-15-00000000-0000-4000-8000-000000000000\semantic-output.json",
        ]
    )
    assert standalone_historical.handler is standalone.successor_v3_historical_check
    assert standalone_historical.expected_c3 == "1" * 40
    assert standalone_historical.expected_a3 == "2" * 40
    assert not hasattr(standalone_historical, "repository_root")
    assert not hasattr(standalone_historical, "package")
    with pytest.raises(
        standalone.GovernanceError,
        match="commands require successful frozen runtime bootstrap",
    ):
        standalone_historical.handler(standalone_historical)
    for name in _SYNTHETIC_FROZEN_RUNTIME_FIELDS:
        monkeypatch.setattr(standalone, name, getattr(governance, name))
    monkeypatch.setattr(standalone, "TRUSTED_EXECUTABLE_IDENTITIES", trusted_tools)
    monkeypatch.setattr(standalone, "MAINTAINER_PUBLIC_KEY", signing_key.public_key)
    monkeypatch.setattr(
        standalone,
        "POST_R2_PROCESS_TEMP_ROOT",
        governance.POST_R2_PROCESS_TEMP_ROOT,
    )
    monkeypatch.setattr(
        standalone,
        "MAINTAINER_KEY_FINGERPRINT",
        signing_key.fingerprint,
    )
    synthetic_post_r2 = governance._read_json(post_r2_evidence)
    synthetic_post_r2_command = synthetic_post_r2["command"]
    monkeypatch.setattr(
        standalone,
        "_post_r2_test_runtime_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(synthetic_post_r2_command["test_runtime"]),
    )
    monkeypatch.setattr(
        standalone,
        "_post_r2_test_surface_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(synthetic_post_r2["repository_test_surface"]),
    )
    monkeypatch.setattr(
        standalone,
        "_generation_1_supersession_binding",
        lambda *_args, **_kwargs: predecessor_binding,
    )
    monkeypatch.setattr(
        standalone,
        "_load_corrective_authorization_from_result",
        lambda _snapshot, root, commit: standalone._read_json_from_commit(
            root,
            commit,
            "docs/governance/v1/corrective-kickoff-authorization.json",
        ),
    )

    def validate_predecessor(root: Path, *, expected_roadmap_digest: str) -> dict[str, Any]:
        assert expected_roadmap_digest == snapshot.raw_digest
        record = standalone._read_tagged_current_acceptance_attestation(
            root,
            tag_object=standalone.S1_ACCEPTANCE_V1_TAG_OBJECT,
            expected_closure_commit=standalone.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        )
        assert record["format"] == standalone.CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT
        return record

    monkeypatch.setattr(
        standalone,
        "_validate_generation_1_predecessor_acceptance",
        validate_predecessor,
    )
    monkeypatch.setattr(
        standalone,
        "validate_approval_roster",
        lambda *_args, **_kwargs: (roster_digest, person_id),
    )
    for name in (
        "validate_maintainer_signing_key",
        "validate_corrective_kickoff_authorization",
        "validate_baseline_observations",
        "validate_kickoff_authorization",
        "validate_estimation_catalog_v2",
        "validate_authoring_ledger_v2",
        "validate_forecast_v2",
    ):
        monkeypatch.setattr(standalone, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        standalone,
        "_resolve_aggregation_method_v2",
        lambda *_args, **_kwargs: {},
    )
    validate_schema = standalone._validate_json_schema

    def validate_schema_except_synthetic_registry(
        instance: object,
        schema: Mapping[str, Any],
        *,
        owner: str,
    ) -> None:
        if owner != "aggregation method registry":
            validate_schema(instance, schema, owner=owner)

    monkeypatch.setattr(
        standalone,
        "_validate_json_schema",
        validate_schema_except_synthetic_registry,
    )
    arguments = Namespace(
        repository_root=str(repository),
        governance_dir=str(repository / "docs/governance/v1"),
        roadmap=str(roadmap),
        acceptance_generation=2,
        allow_pending=False,
        accept_now=False,
        historical=True,
        closure_commit=closure_commit,
        acceptance_tag_object=tag_object,
        fetch_authoritative_refs=False,
        commitment_time=None,
        attestation_plan_dir=None,
        attestation_signed_at=None,
    )
    assert standalone.check.__wrapped__(arguments) == 0
    output = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert output == {
        "acceptance_tag_object": tag_object,
        "bundle_digest": bundle["bundle_digest"],
        "bundle_status": "accepted_for_development",
        "forecast_status": "accepted",
        "record_digest": forecast["record_digest"],
        "result": "valid_historical_accepted",
        "signatures": "all_required_verified",
    }

    later = repository / "later-generation.txt"
    later.write_text("later generation descendant\n", encoding="utf-8", newline="\n")
    _commit_paths(repository, "later generation descendant", [later.name])
    with pytest.raises(
        standalone.GovernanceError,
        match="exact closure commit",
    ):
        standalone.check.__wrapped__(arguments)
