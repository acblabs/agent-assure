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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.schema_versions import SCHEMA_ROOT, frozen_schema_versions  # noqa: E402

DIST = ROOT / "dist"
LOCKFILE = ROOT / "requirements.lock"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        wheel = find_single_wheel(args.dist)
        run(
            [sys.executable, "-c", _direct_wheel_zip_import_assertion(wheel)],
            cwd=ROOT,
        )
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
            run(
                [
                    str(python),
                    "-c",
                    _installed_wheel_campaign_assertion(),
                ],
                cwd=temp_dir,
            )
            run(
                [
                    str(python),
                    "-c",
                    _demo_network_guard_assertion(),
                ],
                cwd=temp_dir,
            )
            run([str(agent_assure), "--version"], cwd=temp_dir)
            run(
                [str(agent_assure), "controls", "mutate", "--help"],
                cwd=temp_dir,
            )
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


def _direct_wheel_zip_import_assertion(wheel: Path) -> str:
    wheel_path = str(wheel.resolve())
    return (
        "import sys; "
        f"wheel = {wheel_path!r}; "
        "sys.path.insert(0, wheel); "
        "import agent_assure; "
        "assert wheel in agent_assure.__file__; "
        "from agent_assure.cli.main import app; "
        "assert app is not None; "
        "from agent_assure.mutation.catalog import registered_operators; "
        "from agent_assure.mutation.campaign import build_core_catalog; "
        "operators = registered_operators(); "
        "assert len(operators) == 7; "
        "catalog = build_core_catalog(operators); "
        "assert catalog.catalog_id == 'core/v1'; "
        "assert len(catalog.operators) == 7"
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
        "streaming_process_regression/suite.yaml",
        "streaming_process_regression/events/candidate_retry_burst.jsonl",
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


def _installed_wheel_campaign_assertion() -> str:
    """Return an offline core-catalog campaign exercised only from installed code."""
    return """
from copy import deepcopy
import socket
import sys

_connect_probe = socket.socket()
_connect_ex_probe = socket.socket()
_blocked_network_events = []

def reject_network_helper(*_args, **_kwargs):
    _blocked_network_events.append("socket-helper")
    raise AssertionError("mutation campaign attempted network access")

def reject_socket_audit_event(event, _args):
    if event.startswith("socket."):
        _blocked_network_events.append(event)
        raise AssertionError("mutation campaign attempted network access")

socket.create_connection = reject_network_helper
socket.getaddrinfo = reject_network_helper
sys.addaudithook(reject_socket_audit_event)

for probe, operation in (
    (_connect_probe, "connect"),
    (_connect_ex_probe, "connect_ex"),
):
    try:
        getattr(probe, operation)(("127.0.0.1", 9))
    except AssertionError:
        pass
    else:
        raise AssertionError(f"raw socket {operation} bypassed the network guard")
    finally:
        probe.close()

assert len(_blocked_network_events) == 2
_guard_probe_event_count = len(_blocked_network_events)

from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation.campaign import execute_mutation_campaign
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults

suite = CompiledSuite(
    suite_id="installed-wheel-campaign",
    suite_version="1.0.0",
    cases=(
        SuiteCase(
            case_id="case-a",
            title="Installed wheel campaign",
            expectation_id="expectation-a",
        ),
    ),
    resolved_expectations=(
        Expectation(
            expectation_id="expectation-a",
            case_id="case-a",
            material_claim_ids=("claim-a",),
            forbidden_tools=("blocked-tool",),
            required_human_review=True,
        ),
    ),
    defaults=SuiteDefaults(
        runner_id="installed.wheel",
        allowed_tools=("safe-tool",),
    ),
    source_digest="a" * 64,
)
fixture_digest = "b" * 64
runset = RunSet(
    runset_id="installed-wheel-campaign-runset",
    privacy_profile_id=PRIVACY_PROFILE_ID,
    privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
    suite_id=suite.suite_id,
    suite_version=suite.suite_version,
    suite_digest=compiled_suite_digest(suite),
    fixture_manifest_digest=fixture_digest,
    runs=(
        AgentRunRecord(
            run_id="run-a",
            case_id="case-a",
            pipeline_id="installed.wheel",
            recommendation="approve",
            outcome="approved",
            input_summary="synthetic fixture input",
            output_summary="synthetic fixture output",
            tools=("safe-tool",),
            evidence_refs=(
                EvidenceRef(
                    ref_id="evidence-a",
                    source_id="source-a",
                    claim_ids=("claim-a",),
                ),
            ),
            evidence_items=(
                EvidenceItem(
                    ref_id="evidence-a",
                    source_id="source-a",
                    content_digest="c" * 64,
                ),
            ),
            claim_evidence_links=(
                ClaimEvidenceLink(
                    claim_id="claim-a",
                    evidence_ref_id="evidence-a",
                ),
            ),
            human_review_required=True,
            human_review_performed=True,
            provenance=Provenance(fixture_manifest_digest=fixture_digest),
        ),
    ),
)
source = runset.model_dump(mode="json")
source_snapshot = deepcopy(source)
kwargs = {
    "seed": 17,
    "generated_at": "2026-07-29T00:00:00Z",
}
first = execute_mutation_campaign(suite, source, **kwargs)
second = execute_mutation_campaign(suite, source, **kwargs)

assert source == source_snapshot
assert first.catalog.catalog_id == "core/v1"
assert len(first.catalog.operators) == 7
canonical_order = tuple(item.descriptor.operator_id for item in first.catalog.operators)
assert canonical_order == tuple(sorted(canonical_order))
assert first.campaign.canonical_operator_order == canonical_order
assert first.campaign.selected_operator_order == canonical_order
assert first.campaign.executed_operator_order == canonical_order
assert first.campaign.pending_operator_order == ()
assert len(first.campaign.operator_results) == 7
assert all(item.result.state.value == "caught" for item in first.campaign.operator_results)
assert first.campaign.campaign_digest == second.campaign.campaign_digest
assert len(_blocked_network_events) == _guard_probe_event_count
"""


def _demo_network_guard_assertion() -> str:
    probe = "import socket; socket.create_connection(('127.0.0.1', 9))"
    expected = "network access is disabled for agent-assure demo subprocesses"
    return (
        "from pathlib import Path; "
        "import os, subprocess, sys; "
        "from agent_assure.demo.common import demo_subprocess_env; "
        "out = Path.cwd() / 'network-guard-check'; "
        "out.mkdir(parents=True, exist_ok=True); "
        "env = demo_subprocess_env(out, env=os.environ.copy()); "
        f"result = subprocess.run([sys.executable, '-c', {probe!r}], "
        "cwd=out, env=env, text=True, capture_output=True, check=False); "
        f"expected = {expected!r}; "
        "raise SystemExit(0 if result.returncode != 0 and expected in result.stderr "
        "else 'demo network guard did not block socket creation')"
    )


def _frozen_schema_resource_paths(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    versions = schema_versions or frozen_schema_versions(schema_root)
    paths: list[str] = []
    for version in versions:
        version_dir = schema_root / version
        paths.extend(
            f"{version}/{path.name}"
            for path in sorted(version_dir.glob("*.schema.json"))
        )
    return tuple(paths)


if __name__ == "__main__":
    raise SystemExit(main())
