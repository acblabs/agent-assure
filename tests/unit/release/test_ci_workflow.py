from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]


def test_release_validating_ci_job_fetches_full_history() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    test_job = workflow.split("  test:\n", maxsplit=1)[1].split(
        "  schema-immutability:\n", maxsplit=1
    )[0]

    assert "fetch-depth: 0" in test_job
    assert "make release-check" in test_job


def test_windows_containment_ci_covers_native_boundaries_without_full_release_matrix() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = workflow.split("  windows-containment:\n", maxsplit=1)[1].split(
        "  schema-immutability:\n", maxsplit=1
    )[0]

    assert "runs-on: windows-2025" in job
    assert "windows-latest" not in workflow
    assert 'python-version: ["3.11", "3.14"]' in job
    assert "tests/unit/runner" in job
    assert "tests/unit/test_rooted_io.py" in job
    assert job.count("python -m pytest") == 2
    assert job.count("--fail-on-skip") == 1
    assert "test_rooted_read_rejects_linked_parent_escape" in job
    assert "test_rooted_directory_lease_blocks_lexical_rename_until_close" in job
    assert (
        "tests/unit/test_rooted_io.py::"
        "test_rooted_directory_claim_owns_independent_pins_and_writer_operations"
    ) in job
    assert (
        "tests/unit/test_rooted_io.py::"
        "test_windows_rooted_directory_claim_blocks_rename_until_close"
    ) in job
    assert (
        "tests/integration/test_evidence_sensitivity_cli.py::"
        "test_responsive_subject_emits_a_verdict_bearing_pass_and_renderings"
    ) in job
    assert "test_external_script_timeout_terminates_descendant_process_tree" in job
    assert "test_post_spawn_validation_failure_terminates_and_reaps_suspended_process" in job
    assert "test_windows_external_script_success_kills_descendant_when_job_closes" in job
    assert "make release-check" not in job


def test_ci_qualifies_declared_dependency_lower_bounds_on_supported_python_edges() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    job = workflow["jobs"]["dependency-lower-bounds"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert 120 <= job["timeout-minutes"] <= 180
    assert job["strategy"] == {
        "fail-fast": False,
        "matrix": {"python-version": ["3.11", "3.14"]},
    }
    steps = job["steps"]
    checkout = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    setup = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/setup-python@")
    )
    assert setup["with"]["python-version"] == "${{ matrix.python-version }}"

    commands = "\n".join(str(step.get("run", "")) for step in steps)
    assert "python -m pip install --require-hashes -r requirements-min.lock" in commands
    assert "python -m pip install --no-deps --no-build-isolation ." in commands
    assert "python -m pip install --no-deps --no-build-isolation -e ." not in commands
    assert (
        "python scripts/check_dependency_lock_freshness.py --verify-installed-minimums"
    ) in commands
    assert "python -m pip check" in commands
    assert "python -m pytest -q -p no:cacheprovider" in commands
    assert "$RUNNER_TEMP/pytest-dependency-lower-bounds" in commands
    assert commands.index(
        "python -m pip install --no-deps --no-build-isolation ."
    ) < commands.index("python scripts/check_dependency_lock_freshness.py")
    assert commands.index("python scripts/check_dependency_lock_freshness.py") < commands.index(
        "python -m pip check"
    )
    assert commands.index("python -m pip check") < commands.index("python -m pytest")
    for forbidden in (
        "make check",
        "make release-check",
        "python -m build",
        "scripts/update_golden.py",
    ):
        assert forbidden not in commands
    assert not any(
        str(step.get("uses", "")).startswith("actions/upload-artifact@") for step in steps
    )


def test_ci_runs_local_composite_action_migration_profile_on_a_real_runner() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert workflow["permissions"] == {"contents": "read"}

    job = workflow["jobs"]["composite-action-smoke"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert 0 < job["timeout-minutes"] <= 30
    steps = job["steps"]
    action_step = next(
        step for step in steps if step.get("uses") == "./.github/actions/agent-assure"
    )
    assert "continue-on-error" not in action_step
    assert action_step["with"] == {
        "suite": "examples/prior_auth_synthetic/suite.yaml",
        "candidate-variant": "examples/prior_auth_synthetic/variants/baseline.yaml",
        "out-dir": "${{ runner.temp }}/agent-assure-composite-smoke",
        "report-mode": "full",
        "allow-missing-efficacy-for-migration": "true",
        "upload-reports": "false",
        "upload-full-artifacts": "false",
    }
    commands = "\n".join(str(step.get("run", "")) for step in steps)
    assert "pip install --require-hashes -r requirements.lock" in commands
    assert "reports/evidence-packet.json" in commands
    assert "reports/release-artifact-manifest.json" in commands
    assert "agent-assure validate" in commands
    assert "--kind evidence-packet" in commands
    assert not any(
        str(step.get("uses", "")).startswith("actions/upload-artifact@") for step in steps
    )


def test_ci_runs_local_composite_action_strict_profile_on_a_real_runner() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    job = workflow["jobs"]["composite-action-strict-smoke"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert 0 < job["timeout-minutes"] <= 30
    steps = job["steps"]
    action_step = next(
        step for step in steps if step.get("uses") == "./.github/actions/agent-assure"
    )
    assert "continue-on-error" not in action_step
    assert action_step["with"] == {
        "suite": "examples/prior_auth_synthetic/suite.yaml",
        "candidate-variant": "examples/prior_auth_synthetic/variants/baseline.yaml",
        "out-dir": ".tmp/agent-assure-composite-strict",
        "report-mode": "full",
        "control-efficacy-report": (
            ".tmp/composite-strict-efficacy/control-efficacy/control-efficacy-report.json"
        ),
        "efficacy-policy": ".tmp/composite-strict-efficacy/controls-mutation.yaml",
        "upload-reports": "false",
        "upload-full-artifacts": "false",
    }
    assert "allow-missing-efficacy-for-migration" not in action_step["with"]
    assert "runner.temp" not in action_step["with"]["out-dir"]

    strict_input_step = next(
        step for step in steps if step.get("name") == "Build deterministic strict-efficacy inputs"
    )
    strict_input_commands = str(strict_input_step["run"])
    assert (
        "agent-assure suite compile examples/prior_auth_synthetic/suite.yaml"
        in strict_input_commands
    )
    assert "--variant examples/prior_auth_synthetic/variants/baseline.yaml" in strict_input_commands
    assert "--out .tmp/composite-strict-efficacy/runset.json" in strict_input_commands
    assert "suite_path: suite.compiled.json" in strict_input_commands
    assert "agent-assure doctor controls-mutate" in strict_input_commands
    assert "--suite .tmp/composite-strict-efficacy/suite.compiled.json" in strict_input_commands
    assert "--suite .tmp/composite-strict-efficacy/suite.yaml" not in strict_input_commands

    commands = "\n".join(str(step.get("run", "")) for step in steps)
    assert "agent-assure init controls-mutation" in commands
    assert "agent-assure controls mutate" in commands
    assert "agent-assure controls efficacy" in commands
    assert "reports/evidence-packet.json" in commands
    assert "reports/assurance-evidence-graph.json" in commands
    assert "reports/release-artifact-manifest.json" in commands
    assert "agent-assure validate" in commands
    assert "--kind evidence-packet" in commands
    assert "agent-assure ci gate" in commands
    assert "--efficacy-policy" in commands
    assert "--require-efficacy" in commands
    assert "--fail-on-warn" in commands
    assert "--fail-on-not-evaluated" in commands
    assert "--allow-missing-efficacy-for-migration" not in commands
    assert not any(
        str(step.get("uses", "")).startswith("actions/upload-artifact@") for step in steps
    )


def test_evidence_build_and_reproduction_jobs_fetch_full_history() -> None:
    workflow = (ROOT / ".github" / "workflows" / "evidence.yml").read_text(encoding="utf-8")

    assert workflow.count("fetch-depth: 0") == 2
    assert workflow.count("python scripts/build_release_bundle.py") == 2
    assert workflow.count("--expected-release") == 2


def test_adk_smoke_installs_locked_dependency_and_cannot_silently_skip() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    adk_job = workflow.split("  adk-smoke:\n", maxsplit=1)[1]

    assert "pip install --require-hashes -r requirements-adk.lock" in adk_job
    assert "from google.adk.events.event import Event" in adk_job
    assert "from google.adk.events.event_actions import EventActions" in adk_job
    assert 'pip install --no-deps --no-build-isolation ".[adk]"' not in adk_job

    lockfile = (ROOT / "requirements-adk.lock").read_text(encoding="utf-8")
    assert "\ngoogle-adk==" in lockfile


def test_langgraph_smoke_runs_the_full_real_equivalence_file() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    langgraph_job = workflow.split("  langgraph-smoke:\n", maxsplit=1)[1].split(
        "  adk-smoke:\n", maxsplit=1
    )[0]

    assert "from langgraph.graph import StateGraph" in langgraph_job
    assert "tests/integration/test_langgraph_expense_assurance.py" in langgraph_job
    assert "test_langgraph_real_graph_stream_smoke" not in langgraph_job


def test_otel_contract_installs_locked_dependencies_and_cannot_silently_skip() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    otel_job = workflow.split("  otel-contract:\n", maxsplit=1)[1]

    assert "pip install --require-hashes -r requirements-otel.lock" in otel_job
    assert "from opentelemetry.context import Context" in otel_job
    assert "from opentelemetry.sdk.trace import TracerProvider" in otel_job
    assert (
        "from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter"
    ) in otel_job
    assert "--fail-on-skip" in otel_job
    assert '--basetemp "$RUNNER_TEMP/pytest-otel-contract"' in otel_job
    assert "--basetemp .tmp/pytest-otel-contract" not in otel_job
    assert "tests/unit/telemetry/test_otel_sdk.py" in otel_job
    assert "tests/unit/test_otel_cli.py" in otel_job
    assert "test_emit_span_plans_pins_resource_sampler_limits_and_root_context" not in otel_job

    lockfile = (ROOT / "requirements-otel.lock").read_text(encoding="utf-8")
    assert "\nopentelemetry-api==1.44.0" in lockfile
    assert "\nopentelemetry-sdk==1.44.0" in lockfile
    assert "\nopentelemetry-exporter-otlp-proto-http==1.44.0" in lockfile

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["optional-dependencies"]["otel"] == [
        "opentelemetry-api==1.44.0",
        "opentelemetry-sdk==1.44.0",
        "opentelemetry-exporter-otlp-proto-http==1.44.0",
    ]


def test_testpypi_schema_checks_have_full_history_and_cannot_silently_skip() -> None:
    workflow = (ROOT / ".github" / "workflows" / "publish-testpypi.yml").read_text(encoding="utf-8")
    parsed_workflow = yaml.safe_load(workflow)

    assert workflow.count("fetch-depth: 0") == 3
    assert (
        workflow.count("python scripts/check_tagged_schema_immutability.py --require-release-tags")
        == 2
    )
    assert workflow.count('make release-publish-check EXPECTED_RELEASE="${EXPECTED_VERSION}"') == 1
    assert 'make release-publish-check EXPECTED_RELEASE="${EXPECTED_RELEASE}"' in workflow
    reproduce = parsed_workflow["jobs"]["reproduce"]
    checkout = next(
        step
        for step in reproduce["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
        "ref": "${{ needs.build.outputs.source_sha }}",
    }
    commands = "\n".join(str(step.get("run", "")) for step in reproduce["steps"])
    assert 'test "$(git rev-parse HEAD)" = "${EXPECTED_SOURCE_SHA}"' in commands


def test_testpypi_checks_committed_version_bound_goldens_before_release_checks() -> None:
    workflow = (ROOT / ".github" / "workflows" / "publish-testpypi.yml").read_text(encoding="utf-8")
    build_job, remainder = workflow.split("  reproduce:\n", maxsplit=1)
    reproduce_job = remainder.split("  testpypi-publish:\n", maxsplit=1)[0]

    assert workflow.count("Verify committed version-bound deterministic goldens") == 2
    assert "include matching committed version-bound deterministic goldens" in workflow
    assert "for example 0.6.4rc1" in workflow
    for job in (build_job, reproduce_job):
        assert job.index("python scripts/update_golden.py") < job.index(
            "make release-publish-check"
        )


def test_every_checkout_disables_persisted_credentials() -> None:
    workflows = tuple((ROOT / ".github" / "workflows").glob("*.yml"))
    for path in workflows:
        workflow = path.read_text(encoding="utf-8")
        assert workflow.count("persist-credentials: false") == workflow.count(
            "uses: actions/checkout@"
        ), path.name


def test_github_owned_javascript_actions_use_verified_node24_pins() -> None:
    expected = {
        "actions/attest": "1e69f48acb82d1966a394da916b4c1698aa569d6",
        "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    }
    paths = tuple((ROOT / ".github").rglob("*.yml"))
    seen: set[str] = set()

    for path in paths:
        workflow = path.read_text(encoding="utf-8")
        for action, revision in re.findall(
            r"uses:\s+(actions/(?:attest|checkout|setup-python|upload-artifact|"
            r"download-artifact))@([^\s#]+)",
            workflow,
        ):
            seen.add(action)
            assert revision == expected[action], (path.name, action)
    assert seen == set(expected)


def test_every_linux_workflow_job_pins_ubuntu_2404() -> None:
    for path in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "ubuntu-latest" not in text, path.name
        workflow = yaml.safe_load(text)
        for job in workflow.get("jobs", {}).values():
            runner = job.get("runs-on")
            if isinstance(runner, str) and runner.startswith("ubuntu-"):
                assert runner == "ubuntu-24.04", (path.name, runner)


def test_artifact_id_downloads_merge_into_the_exact_requested_path() -> None:
    expected_downloads = {
        "release.yml": 14,
        "publish-testpypi.yml": 3,
        "evidence.yml": 4,
    }

    for workflow_name, expected_count in expected_downloads.items():
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        )
        downloads = [
            step
            for job in workflow["jobs"].values()
            for step in job.get("steps", ())
            if isinstance(step, dict)
            and str(step.get("uses", "")).startswith("actions/download-artifact@")
            and "artifact-ids" in step.get("with", {})
        ]

        assert len(downloads) == expected_count, workflow_name
        assert all(step["with"].get("path") for step in downloads), workflow_name
        assert all(step["with"].get("merge-multiple") is True for step in downloads), workflow_name


def test_release_fresh_job_verifies_and_forwards_the_exact_uploaded_ids() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    producer = jobs["verify-signatures"]
    assert producer["outputs"] == {
        "distributions_artifact_id": ("${{ steps.upload-distributions.outputs.artifact-id }}"),
        "verified_signed_bundle_artifact_id": (
            "${{ steps.upload-verified-bundle.outputs.artifact-id }}"
        ),
    }
    distribution_upload = next(
        step for step in producer["steps"] if step.get("id") == "upload-distributions"
    )
    assert distribution_upload["name"] == "Upload verified distributions by immutable artifact ID"
    fresh = jobs["verify-uploaded-artifacts"]
    assert fresh["needs"] == "verify-signatures"
    assert fresh["permissions"] == {"contents": "read"}
    assert fresh["outputs"] == {
        "distributions_artifact_id": (
            "${{ steps.verify-uploaded.outputs.distributions_artifact_id }}"
        ),
        "provenance_subjects_artifact_id": (
            "${{ steps.upload-provenance-subjects.outputs.artifact-id }}"
        ),
        "verified_signed_bundle_artifact_id": (
            "${{ steps.verify-uploaded.outputs.verified_signed_bundle_artifact_id }}"
        ),
    }
    assert all("continue-on-error" not in step for step in fresh["steps"])
    uploads = [
        step
        for step in fresh["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    assert uploads[0]["id"] == "upload-provenance-subjects"
    assert uploads[0]["with"] == {
        "name": "release-provenance-subjects-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": ".tmp/release-provenance-subjects.sha256",
        "if-no-files-found": "error",
        "retention-days": 30,
    }
    assert not any(
        "pip install --no-deps --no-build-isolation -e ." in str(step.get("run", ""))
        for step in fresh["steps"]
    )

    downloads = {
        step["with"]["path"]: step
        for step in fresh["steps"]
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    }
    assert set(downloads) == {".tmp/release", ".tmp/distributions"}
    assert downloads[".tmp/release"]["with"]["artifact-ids"] == (
        "${{ needs.verify-signatures.outputs.verified_signed_bundle_artifact_id }}"
    )
    assert downloads[".tmp/distributions"]["with"]["artifact-ids"] == (
        "${{ needs.verify-signatures.outputs.distributions_artifact_id }}"
    )

    validation = next(step for step in fresh["steps"] if step.get("id") == "verify-uploaded")
    assert validation["id"] == "verify-uploaded"
    assert validation["env"] == {
        "DISTRIBUTIONS_ARTIFACT_ID": (
            "${{ needs.verify-signatures.outputs.distributions_artifact_id }}"
        ),
        "VERIFIED_BUNDLE_ARTIFACT_ID": (
            "${{ needs.verify-signatures.outputs.verified_signed_bundle_artifact_id }}"
        ),
    }
    command = validation["run"]
    assert "cosign_release_artifacts.py verify-uploaded" in command
    assert "--distributions-dir .tmp/distributions" in command
    assert "--require-release-notes" in command
    assert command.index("verify-uploaded") < command.index("verified_signed_bundle_artifact_id=%s")
    assert 'test "${VERIFIED_BUNDLE_ARTIFACT_ID}" != ' in command
    assert "ARTIFACT_DIGEST" not in command
    assert "artifact_digest" not in command
    assert 'test "${#release_assets[@]}" -eq 22' in command
    assert "release-provenance-subjects.sha256" in command
    assert '[[ "${digest}" =~ ^[0-9a-f]{64}$ ]]' in command
    assert "sort -u | wc -l" in command
    assert command.index("cosign_release_artifacts.py verify-uploaded") < command.index(
        "release_assets=("
    )
    assert fresh["steps"].index(validation) < fresh["steps"].index(uploads[0])

    github_release = jobs["github-release"]
    assert github_release["needs"] == [
        "verify-uploaded-artifacts",
        "attest-release-provenance",
    ]
    assert github_release["steps"][0]["with"]["artifact-ids"] == (
        "${{ needs.verify-uploaded-artifacts.outputs.verified_signed_bundle_artifact_id }}"
    )
    pypi = jobs["pypi-publish"]
    assert pypi["needs"] == [
        "verify-uploaded-artifacts",
        "attest-release-provenance",
        "github-release",
    ]
    assert pypi["steps"][0]["with"]["artifact-ids"] == (
        "${{ needs.verify-uploaded-artifacts.outputs.distributions_artifact_id }}"
    )


def test_release_attestation_is_exact_least_privilege_and_fail_closed() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    job = jobs["attest-release-provenance"]

    assert job["needs"] == "verify-uploaded-artifacts"
    assert job["environment"] == {"name": "signing"}
    assert job["permissions"] == {
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
    }
    assert job["runs-on"] == "ubuntu-24.04"
    assert 0 < job["timeout-minutes"] <= 15
    assert "startsWith(github.ref, 'refs/tags/v')" in job["if"]
    assert "inputs.operation == 'standard'" in job["if"]

    steps = job["steps"]
    assert len(steps) == 2
    assert all("continue-on-error" not in step for step in steps)
    assert all("run" not in step for step in steps)
    assert all("env" not in step for step in steps)
    assert all("actions/checkout@" not in str(step.get("uses", "")) for step in steps)
    assert all("actions/setup-python@" not in str(step.get("uses", "")) for step in steps)

    download, attest = steps
    assert download["uses"] == (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    )
    assert download["with"] == {
        "artifact-ids": (
            "${{ needs.verify-uploaded-artifacts.outputs.provenance_subjects_artifact_id }}"
        ),
        "merge-multiple": True,
        "path": ".tmp/provenance-subjects",
    }
    assert attest["uses"] == "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
    assert attest["with"] == {
        "subject-checksums": (".tmp/provenance-subjects/release-provenance-subjects.sha256")
    }

    verification = next(
        step
        for step in jobs["verify-uploaded-artifacts"]["steps"]
        if step.get("id") == "verify-uploaded"
    )
    command = verification["run"]
    expected_assets = {
        ".tmp/release/reports/evidence-packet.json",
        ".tmp/release/reports/evidence-packet.json.bundle",
        ".tmp/release/reports/evidence-packet.md",
        ".tmp/release/reports/evidence-packet.md.bundle",
        ".tmp/release/reports/evaluation-summary.json",
        ".tmp/release/reports/evaluation-summary.json.bundle",
        ".tmp/release/reports/comparison-summary.json",
        ".tmp/release/reports/comparison-summary.json.bundle",
        ".tmp/release/reports/assurance-evidence-graph.json",
        ".tmp/release/reports/assurance-evidence-graph.json.bundle",
        ".tmp/release/reports/release-artifact-manifest.json",
        ".tmp/release/reports/release-artifact-manifest.json.bundle",
        ".tmp/release/release-digest-replay.json",
        ".tmp/release/release-digest-replay.json.bundle",
        ".tmp/release/release-notes.md",
        ".tmp/release/release-notes.md.bundle",
        ".tmp/release/sbom.cdx.json",
        ".tmp/release/sbom.cdx.json.bundle",
    }
    assert all(asset in command for asset in expected_assets)
    assert "-name '*.whl'" in command
    assert "-name '*.whl.bundle'" in command
    assert "-name '*.tar.gz'" in command
    assert "-name '*.tar.gz.bundle'" in command
    assert 'test "${#distributions[@]}" -eq 4' in command
    assert 'test "${#release_assets[@]}" -eq 22' in command
    assert 'test "$(wc -l < .tmp/release-provenance-subjects.sha256)" -eq 22' in command
    assert "sort -u | wc -l" in command

    assert jobs["github-release"]["needs"] == [
        "verify-uploaded-artifacts",
        "attest-release-provenance",
    ]
    assert jobs["pypi-publish"]["needs"] == [
        "verify-uploaded-artifacts",
        "attest-release-provenance",
        "github-release",
    ]


def test_evidence_fresh_job_verifies_the_exact_uploaded_id_without_reupload() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "evidence.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    producer = jobs["verify"]
    assert producer["outputs"] == {
        "verified_signed_bundle_artifact_id": (
            "${{ steps.upload-verified-bundle.outputs.artifact-id }}"
        ),
    }
    upload = next(
        step
        for step in producer["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    )
    assert upload["id"] == "upload-verified-bundle"

    fresh = jobs["verify-uploaded-artifacts"]
    assert fresh["needs"] == "verify"
    assert fresh["permissions"] == {"contents": "read"}
    assert "outputs" not in fresh
    assert not any(
        str(step.get("uses", "")).startswith("actions/upload-artifact@") for step in fresh["steps"]
    )
    assert all("continue-on-error" not in step for step in fresh["steps"])
    assert not any(
        "pip install --no-deps --no-build-isolation -e ." in str(step.get("run", ""))
        for step in fresh["steps"]
    )
    downloads = [
        step
        for step in fresh["steps"]
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    ]
    assert len(downloads) == 1
    assert downloads[0]["with"] == {
        "artifact-ids": ("${{ needs.verify.outputs.verified_signed_bundle_artifact_id }}"),
        "merge-multiple": True,
        "path": ".tmp/release",
    }
    validation = fresh["steps"][-1]
    assert "id" not in validation
    assert validation["env"] == {
        "VERIFIED_BUNDLE_ARTIFACT_ID": (
            "${{ needs.verify.outputs.verified_signed_bundle_artifact_id }}"
        )
    }
    assert "cosign_release_artifacts.py verify-uploaded" in validation["run"]
    assert "--workflow-name evidence" in validation["run"]
    assert "--distributions-dir" not in validation["run"]
    assert "--require-release-notes" not in validation["run"]
    assert "ARTIFACT_DIGEST" not in validation["run"]
    assert "artifact_digest" not in validation["run"]
    assert "GITHUB_OUTPUT" not in validation["run"]
    assert "verified_signed_bundle_artifact_id=%s" not in validation["run"]


def test_release_privileges_are_split_from_build_and_verification() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    build = workflow.split("  build:\n", maxsplit=1)[1].split("  reproduce:\n", maxsplit=1)[0]
    reproduce = workflow.split("  reproduce:\n", maxsplit=1)[1].split(
        "  prepare-release-tag:\n", maxsplit=1
    )[0]
    prepare_tag = workflow.split("  prepare-release-tag:\n", maxsplit=1)[1].split(
        "  sign:\n", maxsplit=1
    )[0]
    sign = workflow.split("  sign:\n", maxsplit=1)[1].split("  verify-signatures:\n", maxsplit=1)[0]
    attest = workflow.split("  attest-release-provenance:\n", maxsplit=1)[1].split(
        "  github-release:\n", maxsplit=1
    )[0]
    pypi = workflow.split("  pypi-publish:\n", maxsplit=1)[1].split(
        "  recover-audit-locks:\n", maxsplit=1
    )[0]

    assert "id-token: write" not in build
    assert "contents: write" not in build
    assert "id-token: write" not in reproduce
    assert "environment:\n      name: release-tag" in prepare_tag
    assert "contents: write" in prepare_tag
    assert "actions: write" in prepare_tag
    assert "id-token: write" not in prepare_tag
    assert "actions/checkout" not in prepare_tag
    assert "id-token: write" in sign
    assert "actions/checkout" not in sign
    assert "setup-python" not in sign
    assert "pip install" not in sign
    assert "id-token: write" in attest
    assert "attestations: write" in attest
    assert "environment:\n      name: signing" in attest
    assert "actions/checkout" not in attest
    assert "setup-python" not in attest
    assert "run:" not in attest
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6" in attest
    assert "actions/checkout" not in pypi
    assert "setup-python" not in pypi
    assert "run:" not in pypi
    assert "artifact-ids:" in pypi


def test_checkout_free_github_release_commands_name_the_repository() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    publish = workflow.split("  github-release:\n", maxsplit=1)[1].split(
        "  pypi-publish:\n", maxsplit=1
    )[0]

    assert "actions/checkout" not in publish
    assert publish.count('--repo "${GITHUB_REPOSITORY}"') == 1
    assert "repos/${GITHUB_REPOSITORY}/releases/tags/${GITHUB_REF_NAME}" in publish
    assert 'release_status="$(awk' in publish
    assert "404)" in publish
    assert "unable to prove release absence" in publish
    assert publish.index(
        "repos/${GITHUB_REPOSITORY}/releases/tags/${GITHUB_REF_NAME}"
    ) < publish.index('gh release create "${GITHUB_REF_NAME}" "${assets[@]}"')


def test_v060_recovery_is_exact_reverification_not_a_rebuild() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    recover_audit = workflow.split("  recover-audit-locks:\n", maxsplit=1)[1].split(
        "  recover-validate-sbom:\n", maxsplit=1
    )[0]
    recover_sbom = workflow.split("  recover-validate-sbom:\n", maxsplit=1)[1].split(
        "  recover-verify:\n", maxsplit=1
    )[0]
    recover_verify = workflow.split("  recover-verify:\n", maxsplit=1)[1].split(
        "  recover-github-release:\n", maxsplit=1
    )[0]
    recover_release = workflow.split("  recover-github-release:\n", maxsplit=1)[1].split(
        "  recover-pypi-publish:\n", maxsplit=1
    )[0]
    recover_pypi = workflow.split("  recover-pypi-publish:\n", maxsplit=1)[1]

    assert "recover-v0.6.0" in workflow
    assert "inputs.operation == 'standard' ||" in workflow
    assert "inputs.operation == 'prepare-tag'" in workflow
    assert "needs: [recover-audit-locks, recover-validate-sbom]" in recover_verify
    assert "needs.recover-audit-locks.result == 'success'" in recover_verify
    assert "needs.recover-validate-sbom.result == 'success'" in recover_verify
    assert "RECOVERY_REF: refs/tags/release-recovery/v0.6.0-30170334180" in (recover_verify)
    assert 'test "${GITHUB_REF}" = "${RECOVERY_REF}"' in recover_verify
    assert 'ORIGINAL_RUN_ID: "30170334180"' in recover_verify
    assert 'ORIGINAL_RUN_ATTEMPT: "1"' in recover_verify
    assert 'ORIGINAL_REPOSITORY_ID: "1280896570"' in recover_verify
    assert 'ORIGINAL_FAILED_JOB_ID: "89710679068"' in recover_verify
    assert "ORIGINAL_TAG: v0.6.0" in recover_verify
    assert "ORIGINAL_SHA: 2c83bafc0e53f25ee27f72179797331d0d7fc5d4" in recover_verify
    assert 'ORIGINAL_BUNDLE_ARTIFACT_ID: "8622776891"' in recover_verify
    assert (
        "ORIGINAL_BUNDLE_ARTIFACT_DIGEST: "
        "sha256:5ab78c65c45fb56b938f3ab7ba0a2bc82eb987fe2a9f1923ec055666fb1a2598" in recover_verify
    )
    assert 'ORIGINAL_BUNDLE_ARTIFACT_SIZE: "1735888"' in recover_verify
    assert 'ORIGINAL_DISTRIBUTIONS_ARTIFACT_ID: "8622776782"' in recover_verify
    assert (
        "ORIGINAL_DISTRIBUTIONS_ARTIFACT_DIGEST: "
        "sha256:9a4b0d78e851a8e2414b5d4a05058e4c259e7ad8a9a7ec02870eb3604e2f27e0" in recover_verify
    )
    assert 'ORIGINAL_DISTRIBUTIONS_ARTIFACT_SIZE: "1665310"' in recover_verify
    assert "actions: read" in recover_verify
    assert "contents: read" in recover_verify
    assert "id-token: write" not in recover_verify
    assert "contents: write" not in recover_verify
    assert "actions/runs/${ORIGINAL_RUN_ID}" in recover_verify
    assert (
        "actions/runs/${ORIGINAL_RUN_ID}/attempts/"
        "${ORIGINAL_RUN_ATTEMPT}/jobs?per_page=100" in recover_verify
    )
    assert "actions/jobs/${ORIGINAL_FAILED_JOB_ID}" in recover_verify
    assert "actions/artifacts/${ORIGINAL_BUNDLE_ARTIFACT_ID}" in recover_verify
    assert "actions/artifacts/${ORIGINAL_DISTRIBUTIONS_ARTIFACT_ID}" in recover_verify
    assert recover_verify.count("github-token: ${{ github.token }}") == 2
    assert recover_verify.count("repository: acblabs/agent-assure") == 2
    assert recover_verify.count("run-id: 30170334180") == 2
    assert "python scripts/build_release_bundle.py" not in recover_verify
    assert "python -m build" not in recover_verify
    parsed_workflow = yaml.safe_load(workflow)
    audit_job = parsed_workflow["jobs"]["recover-audit-locks"]
    assert audit_job["strategy"] == {
        "fail-fast": False,
        "matrix": {
            "os": ["ubuntu-24.04", "windows-2025"],
            "python-version": ["3.11", "3.14"],
        },
    }
    assert audit_job["runs-on"] == "${{ matrix.os }}"
    assert audit_job["permissions"] == {"contents": "read"}
    checkout = next(
        step
        for step in audit_job["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {
        "ref": "2c83bafc0e53f25ee27f72179797331d0d7fc5d4",
        "persist-credentials": False,
    }
    setup = next(
        step
        for step in audit_job["steps"]
        if str(step.get("uses", "")).startswith("actions/setup-python@")
    )
    assert setup["with"]["python-version"] == "${{ matrix.python-version }}"
    recovery_audit_inputs = {
        step["with"]["inputs"]
        for step in audit_job["steps"]
        if str(step.get("uses", "")).startswith("pypa/gh-action-pip-audit@")
    }
    assert recovery_audit_inputs == {
        "requirements.lock",
        "requirements-langgraph.lock",
        "requirements-adk.lock",
        "requirements-otel.lock",
    }
    for step in audit_job["steps"]:
        if str(step.get("uses", "")).startswith("pypa/gh-action-pip-audit@"):
            assert step["uses"] == (
                "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266"
            )
            assert step["with"]["require-hashes"] is True
            assert step["with"]["no-deps"] is True
    assert "gh-action-pip-audit" not in recover_verify
    assert "ubuntu-24.04" in recover_audit
    assert "windows-2025" in recover_audit
    semantic_job = parsed_workflow["jobs"]["recover-validate-sbom"]
    assert semantic_job["needs"] == "recover-audit-locks"
    assert semantic_job["permissions"] == {"actions": "read", "contents": "read"}
    semantic_checkout = next(
        step
        for step in semantic_job["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert semantic_checkout["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": False,
    }
    semantic_download = next(
        step
        for step in semantic_job["steps"]
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    )
    assert semantic_download["with"]["artifact-ids"] == 8622776891
    assert semantic_download["with"]["run-id"] == 30170334180
    assert semantic_download["with"]["repository"] == "acblabs/agent-assure"
    assert "check_legacy_recovery_sbom.py" in recover_sbom
    assert 'test "${GITHUB_REF}" = "${RECOVERY_REF}"' in recover_sbom
    assert 'test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"' in recover_sbom
    assert 'name: "Create immutable GitHub release"' in recover_verify
    assert 'name: "Create release once without replacing assets"' in recover_verify
    assert 'conclusion: "failure"' in recover_verify
    assert "--ref refs/tags/v0.6.0" in recover_verify
    assert "--event-name push" in recover_verify
    assert 'test "${#release_assets[@]}" -eq 16' in recover_verify
    assert "assurance-evidence-graph" not in recover_verify
    assert "actual-release-files.txt" in recover_verify
    assert "non-regular-release-entries.txt" in recover_verify
    assert "test ! -s" in recover_verify
    assert "diff \\" in recover_verify
    assert "< <(" not in recover_verify

    assert "needs: recover-verify" in recover_release
    assert "needs.recover-verify.result == 'success'" in recover_release
    assert "github.event_name == 'workflow_dispatch'" in recover_release
    assert "github.ref == 'refs/tags/release-recovery/v0.6.0-30170334180'" in recover_release
    assert "environment:\n      name: github-release" in recover_release
    assert "contents: read" in recover_release
    assert "contents: write" not in recover_release
    assert "id-token: write" not in recover_release
    assert "actions/checkout" not in recover_release
    assert "setup-python" not in recover_release
    assert "pip install" not in recover_release
    assert (
        "artifact-ids: "
        "${{ needs.recover-verify.outputs.verified_bundle_artifact_id }}" in recover_release
    )
    assert "gh release create" not in recover_release
    assert "gh release upload" not in recover_release
    assert "--method PATCH" not in recover_release
    assert "repos/${GITHUB_REPOSITORY}/releases/tags/${ORIGINAL_TAG}" in (recover_release)
    assert ".draft == false" in recover_release
    assert '.author.login == "acblabs"' in recover_release
    assert ".author.id == 104098411" in recover_release
    assert 'type == "array"' in recover_release
    assert "and length == 16" in recover_release
    assert "assurance-evidence-graph" not in recover_release
    assert '.uploader.login == "acblabs"' in recover_release
    assert ".uploader.id == 104098411" in recover_release
    assert "Accept: application/octet-stream" in recover_release
    assert 'cmp "${local_path}" "${remote_dir}/${asset_name}"' in recover_release
    assert recover_release.count("https://pypi.org/pypi/agent-assure/${ORIGINAL_TAG#v}/json") == 2
    assert "actual-release-files.txt" in recover_release
    assert "non-regular-release-entries.txt" in recover_release
    assert "< <(" not in recover_release

    assert "needs: [recover-verify, recover-github-release]" in recover_pypi
    assert "needs.recover-verify.result == 'success'" in recover_pypi
    assert "needs.recover-github-release.result == 'success'" in recover_pypi
    assert "github.event_name == 'workflow_dispatch'" in recover_pypi
    assert "github.ref == 'refs/tags/release-recovery/v0.6.0-30170334180'" in recover_pypi
    assert "environment:\n      name: pypi" in recover_pypi
    assert "id-token: write" in recover_pypi
    assert "actions/checkout" not in recover_pypi
    assert "setup-python" not in recover_pypi
    assert "run:" not in recover_pypi
    assert (
        "artifact-ids: "
        "${{ needs.recover-verify.outputs.distributions_artifact_id }}" in recover_pypi
    )
    assert parsed_workflow["jobs"]["recover-pypi-publish"]["permissions"] == {"id-token": "write"}


def test_release_tag_creation_is_sha_bound_and_runs_after_unprivileged_gates() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    parsed_workflow = yaml.safe_load(workflow)
    build = workflow.split("  build:\n", maxsplit=1)[1].split("  reproduce:\n", maxsplit=1)[0]
    prepare_tag = workflow.split("  prepare-release-tag:\n", maxsplit=1)[1].split(
        "  resume-release-tag:\n", maxsplit=1
    )[0]
    prepare_job = parsed_workflow["jobs"]["prepare-release-tag"]

    assert "source-sha:" in workflow
    assert "expected-version:" in workflow
    assert (
        "ref: ${{ github.event_name == 'workflow_dispatch' && "
        "inputs.operation == 'prepare-tag' && inputs.source-sha || github.ref }}" in build
    )
    assert '[[ "${REQUESTED_SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]' in build
    assert 'test "${GITHUB_REF}" = "refs/heads/${DEFAULT_BRANCH}"' in build
    assert 'test "${GITHUB_REF}" = "${source_ref}"' in build
    assert 'if [ "${OPERATION}" = "prepare-tag" ]; then' in build
    assert 'test "${GITHUB_SHA}" = "${REQUESTED_SOURCE_SHA}"' in build
    assert 'test "${source_sha}" = "${REQUESTED_SOURCE_SHA}"' in build
    assert 'test "${PACKAGE_VERSION}" = "${REQUESTED_VERSION}"' in build
    assert 'git merge-base --is-ancestor "${source_sha}"' in build
    assert build.index("make release-publish-check") < build.index("Upload exact unsigned")

    required_gates = [
        "build",
        "reproduce",
        "candidate-security",
        "candidate-lower-bounds",
        "candidate-platform-audit",
    ]
    assert prepare_job["needs"] == required_gates
    for gate in required_gates:
        assert f"needs.{gate}.result == 'success'" in prepare_job["if"]
    assert "environment:\n      name: release-tag" in prepare_tag
    assert "contents: write" in prepare_tag
    assert "persist-credentials" not in prepare_tag
    assert '[[ "${GITHUB_RUN_ID}" =~ ^[1-9][0-9]*$ ]]' in prepare_tag
    assert '[[ "${GITHUB_RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]' in prepare_tag
    assert "preflight run ${GITHUB_RUN_ID}; attempt ${GITHUB_RUN_ATTEMPT}" in prepare_tag
    assert "release tag already exists; refusing to move or replace it" in prepare_tag
    assert 'test "${RELEASE_TAG}" = "v${EXPECTED_VERSION}"' in prepare_tag
    assert '"repos/${GITHUB_REPOSITORY}/git/commits/${EXPECTED_SOURCE_SHA}"' in prepare_tag
    assert '"repos/${GITHUB_REPOSITORY}/compare/${EXPECTED_SOURCE_SHA}...' in prepare_tag
    assert "ahead|identical)" in prepare_tag
    assert '"repos/${GITHUB_REPOSITORY}/git/ref/tags/${RELEASE_TAG}"' in prepare_tag
    assert '"repos/${GITHUB_REPOSITORY}/git/tags"' in prepare_tag
    assert '-f object="${EXPECTED_SOURCE_SHA}"' in prepare_tag
    assert '-f ref="refs/tags/${RELEASE_TAG}"' in prepare_tag
    assert "name: Create immutable SHA-bound annotated release tag" in prepare_tag
    assert "name: Verify immutable release tag binding" in prepare_tag
    assert 'jq -er .object.sha)" = "${EXPECTED_SOURCE_SHA}"' in prepare_tag
    assert "name: Dispatch tag-bound publication from the immutable tag" in prepare_tag
    assert '"repos/${GITHUB_REPOSITORY}/actions/workflows/release.yml/dispatches"' in prepare_tag
    assert "-f 'inputs[operation]=standard'" in prepare_tag
    assert '-f "inputs[authorization-run-id]=${GITHUB_RUN_ID}"' in prepare_tag
    assert '-f "inputs[authorization-run-attempt]=${GITHUB_RUN_ATTEMPT}"' in prepare_tag
    assert "inputs[release-profile]" not in prepare_tag
    assert "inputs[security-maintenance-base-tag]" not in prepare_tag
    assert prepare_tag.index('"repos/${GITHUB_REPOSITORY}/git/tags"') < prepare_tag.index(
        '"repos/${GITHUB_REPOSITORY}/git/refs"'
    )
    assert prepare_tag.index('"repos/${GITHUB_REPOSITORY}/git/refs"') < prepare_tag.index(
        '"repos/${GITHUB_REPOSITORY}/actions/workflows/release.yml/dispatches"'
    )
    assert prepare_tag.index(
        "name: Create immutable SHA-bound annotated release tag"
    ) < prepare_tag.index("name: Verify immutable release tag binding")
    assert prepare_tag.index("name: Verify immutable release tag binding") < prepare_tag.index(
        "name: Dispatch tag-bound publication from the immutable tag"
    )


def test_release_tag_operations_share_tag_bound_concurrency_across_dispatch_refs() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "release.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    assert workflow["concurrency"] == {
        "group": (
            "release-${{ github.event_name == 'workflow_dispatch' && "
            "(inputs.operation == 'prepare-tag' || inputs.operation == 'resume-tag') && "
            "format('refs/tags/v{0}', inputs.expected-version) || github.ref }}"
        ),
        "queue": "max",
        "cancel-in-progress": False,
    }


def test_release_tag_recovery_revalidates_and_dispatches_idempotently() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    parsed_workflow = yaml.safe_load(workflow)
    runbook = (ROOT / "docs" / "release_pypi.md").read_text(encoding="utf-8")
    build = workflow.split("  build:\n", maxsplit=1)[1].split("  reproduce:\n", maxsplit=1)[0]
    resume_tag = workflow.split("  resume-release-tag:\n", maxsplit=1)[1].split(
        "  verify-release-tag-provenance:\n", maxsplit=1
    )[0]

    assert "- resume-tag" in workflow
    assert "inputs.operation == 'resume-tag'" in build
    assert "inputs.operation == 'prepare-tag' && inputs.source-sha || github.ref }}" in build
    assert (
        "(inputs.operation == 'prepare-tag' || inputs.operation == 'resume-tag') "
        "&& inputs.source-sha" not in build
    )
    assert 'test "${GITHUB_REF}" = "${source_ref}"' in build
    assert 'test "${GITHUB_SHA}" = "${REQUESTED_SOURCE_SHA}"' in build
    assert 'test "$(git cat-file -t "refs/tags/${release_tag}")" = "tag"' in build
    assert 'test "$(git rev-parse "refs/tags/${release_tag}^{commit}")"' in build
    required_gates = [
        "build",
        "reproduce",
        "candidate-security",
        "candidate-lower-bounds",
        "candidate-platform-audit",
    ]
    resume_job = parsed_workflow["jobs"]["resume-release-tag"]
    assert resume_job["needs"] == required_gates
    for gate in required_gates:
        assert f"needs.{gate}.result == 'success'" in resume_job["if"]
    assert "environment:\n      name: release-tag" in resume_tag
    assert "actions: write" in resume_tag
    assert "contents: read" in resume_tag
    assert "contents: write" not in resume_tag
    assert "actions/checkout" not in resume_tag
    assert 'select(.object.type == "tag") | .object.sha' in resume_tag
    assert 'jq -er .object.type)" = "commit"' in resume_tag
    assert 'jq -er .object.sha)" = "${EXPECTED_SOURCE_SHA}"' in resume_tag
    assert "release tag annotation does not match" in resume_tag
    assert 'preflight_identity="${tag_message#"${annotation_prefix}"}"' in resume_tag
    assert 'preflight_run_id="${preflight_identity%%;*}"' in resume_tag
    assert 'preflight_run_attempt="${preflight_identity#*; attempt }"' in resume_tag
    assert '[[ "${preflight_run_id}" =~ ^[1-9][0-9]*$ ]]' in resume_tag
    assert '[[ "${preflight_run_attempt}" =~ ^[1-9][0-9]*$ ]]' in resume_tag
    assert (
        '[ "${tag_message}" != "${annotation_prefix}${preflight_run_id}; '
        'attempt ${preflight_run_attempt}" ]' in resume_tag
    )
    assert 'case "${tag_message}"' not in resume_tag
    assert (
        '"repos/${GITHUB_REPOSITORY}/actions/runs/${preflight_run_id}/'
        'attempts/${preflight_run_attempt}"' in resume_tag
    )
    assert "(.run_attempt | tostring) == $expected_run_attempt" in resume_tag
    assert '.event == "workflow_dispatch"' in resume_tag
    assert '.path == ".github/workflows/release.yml"' in resume_tag
    assert ".head_branch == $expected_branch" in resume_tag
    assert ".head_sha == $expected_sha" in resume_tag
    assert ".repository.full_name == $expected_repository" in resume_tag
    for conclusion in ("success", "failure", "cancelled", "timed_out"):
        assert f'.conclusion == "{conclusion}"' in resume_tag
    assert (
        '"repos/${GITHUB_REPOSITORY}/actions/runs/${preflight_run_id}/attempts/'
        '${preflight_run_attempt}/jobs?per_page=100"' in resume_tag
    )
    assert "filter=latest" not in resume_tag
    assert "unable to prove release preflight provenance within the bounded job scan" in resume_tag
    assert "def successful_job($name):" in resume_tag
    assert '.workflow_name == "release"' in resume_tag
    assert "successful_job($build_name)" in resume_tag
    assert "successful_job($reproduce_name)" in resume_tag
    assert '--arg create_step "Create immutable SHA-bound annotated release tag"' in resume_tag
    assert "release preflight ended after immutable tag creation" in resume_tag
    assert "unable to prove idempotent tag-bound dispatch" in resume_tag
    assert '.status != "completed" or .conclusion == "success"' in resume_tag
    assert "an active or successful tag-bound release run already exists" in resume_tag
    assert '"repos/${GITHUB_REPOSITORY}/actions/workflows/release.yml/dispatches"' in resume_tag
    assert "-f 'inputs[operation]=standard'" in resume_tag
    assert '-f "inputs[authorization-run-id]=${GITHUB_RUN_ID}"' in resume_tag
    assert '-f "inputs[authorization-run-attempt]=${GITHUB_RUN_ATTEMPT}"' in resume_tag
    assert "inputs[release-profile]" not in resume_tag
    assert "inputs[security-maintenance-base-tag]" not in resume_tag
    assert resume_tag.index("actions/runs/${preflight_run_id}") < resume_tag.index(
        "actions/workflows/release.yml/runs?"
    )
    assert resume_tag.index("actions/workflows/release.yml/runs?") < resume_tag.index(
        "actions/workflows/release.yml/dispatches"
    )
    assert 'release_tag="v0.7.0"' in runbook
    assert 'gh workflow run release.yml --ref "${release_tag}"' in runbook
    assert "workflow from that immutable tag" in runbook


def test_prepare_and_resume_tag_dispatches_cannot_enter_signing_directly() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    sign = workflow.split("  sign:\n", maxsplit=1)[1].split("  verify-signatures:\n", maxsplit=1)[0]

    assert "startsWith(github.ref, 'refs/tags/v')" in sign
    assert "github.event_name != 'workflow_dispatch' || inputs.operation == 'standard'" in sign
    assert "inputs.operation == 'prepare-tag'" not in sign
    assert "inputs.operation == 'resume-tag'" not in sign


def test_release_workflow_exposes_only_standard_fail_closed_publication() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    build = workflow.split("  build:\n", maxsplit=1)[1].split("  reproduce:\n", maxsplit=1)[0]

    assert "release-profile:" not in workflow
    assert "security-maintenance-base-tag:" not in workflow
    assert "security-maintenance" not in workflow
    assert "release-security-maintenance-check" not in workflow
    assert "RELEASE_PROFILE" not in workflow
    assert "SECURITY_MAINTENANCE_BASE_TAG" not in workflow
    assert "Run standard fail-closed release checks" in build
    assert build.count("make release-publish-check") == 1
    assert workflow.count("profile standard; preflight run ") == 4


def test_every_standard_tag_route_requires_protected_attempt_provenance_before_signing() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    parsed_workflow = yaml.safe_load(workflow)
    provenance = workflow.split("  verify-release-tag-provenance:\n", maxsplit=1)[1].split(
        "  sign:\n", maxsplit=1
    )[0]
    sign = workflow.split("  sign:\n", maxsplit=1)[1].split("  verify-signatures:\n", maxsplit=1)[0]

    assert "authorization-run-id:" in workflow
    assert "authorization-run-attempt:" in workflow
    required_gates = [
        "build",
        "reproduce",
        "candidate-security",
        "candidate-lower-bounds",
        "candidate-platform-audit",
    ]
    provenance_job = parsed_workflow["jobs"]["verify-release-tag-provenance"]
    assert provenance_job["needs"] == required_gates
    for gate in required_gates:
        assert f"needs.{gate}.result == 'success'" in provenance_job["if"]
    assert "actions: read" in provenance
    assert "contents: read" in provenance
    assert "id-token: write" not in provenance
    assert "actions/checkout" not in provenance
    assert "startsWith(github.ref, 'refs/tags/v')" in provenance
    assert "AUTHORIZATION_RUN_ID: ${{ inputs.authorization-run-id }}" in provenance
    assert "AUTHORIZATION_RUN_ATTEMPT: ${{ inputs.authorization-run-attempt }}" in provenance
    assert 'test "${GITHUB_REF}" = "refs/tags/${RELEASE_TAG}"' in provenance
    assert 'select(.object.type == "tag") | .object.sha' in provenance
    assert 'preflight_run_id="${preflight_identity%%;*}"' in provenance
    assert 'preflight_run_attempt="${preflight_identity#*; attempt }"' in provenance
    assert provenance.count("actions/runs/${preflight_run_id}/attempts/") == 2
    assert provenance.count("actions/runs/${AUTHORIZATION_RUN_ID}/attempts/") == 2
    assert '.status == "completed" and .conclusion == "success"' in provenance
    assert "successful_job($build_name)" in provenance
    assert "successful_job($reproduce_name)" in provenance
    assert "Create immutable SHA-bound annotated release tag" in provenance
    assert "Resume publication from one verified immutable release tag" in provenance
    assert 'authorization_ref="${DEFAULT_BRANCH}"' in provenance
    assert 'authorization_ref="${RELEASE_TAG}"' in provenance
    assert '--arg expected_branch "${authorization_ref}"' in provenance
    assert "tag-bound publication lacks a successful protected authorization attempt" in provenance
    assert "-gt 100" in provenance
    assert "needs: [reproduce, verify-release-tag-provenance]" in sign


def test_release_requires_reproduction_before_signing_and_publication() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert (
        "needs: [verify-uploaded-artifacts, attest-release-provenance, github-release]" in workflow
    )
    assert "python scripts/assert_dist_reproducible.py" in workflow
    assert workflow.count("--expected-release") == 2
    assert ".tmp/published\n          .tmp/release" in workflow
    assert "--verified-out .tmp/verified-release" in workflow
    assert "--require-clean-source" in workflow
    assert "--clobber" not in workflow
    assert "gh release create" in workflow
    assert "concurrency:" in workflow


def test_current_release_and_evidence_workflows_sign_and_publish_graph() -> None:
    graph = ".tmp/release/reports/assurance-evidence-graph.json"
    evaluation = ".tmp/release/reports/evaluation-summary.json"
    comparison = ".tmp/release/reports/comparison-summary.json"
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    release_sign = release.split("  sign:\n", maxsplit=1)[1].split(
        "  verify-signatures:\n", maxsplit=1
    )[0]
    release_publish = release.split("  github-release:\n", maxsplit=1)[1].split(
        "  pypi-publish:\n", maxsplit=1
    )[0]
    evidence = (ROOT / ".github" / "workflows" / "evidence.yml").read_text(encoding="utf-8")
    evidence_sign = evidence.split("  sign:\n", maxsplit=1)[1].split("  verify:\n", maxsplit=1)[0]

    assert graph in release_sign
    assert graph in evidence_sign
    assert graph in release_publish
    assert f"{graph}.bundle" in release_publish
    for summary in (evaluation, comparison):
        assert summary in release_sign
        assert summary in evidence_sign
        assert summary in release_publish
        assert f"{summary}.bundle" in release_publish
    assert 'test "${#assets[@]}" -eq 22' in release_publish


def test_signers_only_consume_reproducer_promoted_artifacts() -> None:
    for workflow_name in ("release.yml", "evidence.yml"):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        reproduce = workflow.split("  reproduce:\n", maxsplit=1)[1].split("  sign:\n", maxsplit=1)[
            0
        ]
        sign = workflow.split("  sign:\n", maxsplit=1)[1].split(
            "  verify" if workflow_name == "evidence.yml" else "  verify-signatures:\n",
            maxsplit=1,
        )[0]

        assert "verified_bundle_artifact_id:" in reproduce
        assert "path: .tmp/verified-release" in reproduce
        expected_needs = (
            "needs: [reproduce, verify-release-tag-provenance]"
            if workflow_name == "release.yml"
            else "needs: reproduce"
        )
        assert expected_needs in sign
        assert "artifact-ids: ${{ needs.reproduce.outputs.verified_bundle_artifact_id }}" in sign
        assert "needs.build.outputs.bundle_artifact_id" not in sign


def test_github_release_consumes_only_freshly_verified_uploaded_artifact() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    publish = workflow.split("  github-release:\n", maxsplit=1)[1].split(
        "  pypi-publish:\n", maxsplit=1
    )[0]

    assert "needs: [verify-uploaded-artifacts, attest-release-provenance]" in publish
    assert (
        "artifact-ids: "
        "${{ needs.verify-uploaded-artifacts.outputs.verified_signed_bundle_artifact_id }}"
        in publish
    )
    assert "needs.sign.outputs.signed_bundle_artifact_id" not in publish
    assert "needs.verify-signatures.outputs" not in publish


def test_verifiers_upload_only_atomically_promoted_snapshot_views() -> None:
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    release_verify = release.split("  verify-signatures:\n", maxsplit=1)[1].split(
        "  github-release:\n", maxsplit=1
    )[0]
    evidence = (ROOT / ".github" / "workflows" / "evidence.yml").read_text(encoding="utf-8")
    evidence_verify = evidence.split("  verify:\n", maxsplit=1)[1]

    assert "cosign_release_artifacts.py verify-and-promote" in release_verify
    assert "--promotion-dir .tmp/verified-promotion" in release_verify
    assert "path: .tmp/verified-promotion/distributions" in release_verify
    assert "path: .tmp/verified-promotion/release" in release_verify
    assert "cp .tmp/release/dist" not in release_verify
    assert "path: .tmp/publish" not in release_verify
    assert release_verify.index("verify-modified-fails") < release_verify.index(
        "verify-and-promote"
    )
    assert release_verify.index("check_wheel_contents.py") < release_verify.index(
        "verify-and-promote"
    )

    assert "cosign_release_artifacts.py verify-and-promote" in evidence_verify
    assert "--promotion-dir .tmp/verified-promotion" in evidence_verify
    assert "path: .tmp/verified-promotion/release" in evidence_verify
    assert evidence_verify.index("verify-modified-fails") < evidence_verify.index(
        "verify-and-promote"
    )


def test_github_release_rechecks_remote_tag_against_signed_commit() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    publish = workflow.split("  github-release:\n", maxsplit=1)[1].split(
        "  pypi-publish:\n", maxsplit=1
    )[0]

    assert "EXPECTED_RELEASE_SHA: ${{ github.sha }}" in publish
    assert "git/ref/tags/${GITHUB_REF_NAME}" in publish
    assert "git/tags/${tag_sha}" in publish
    assert '"${tag_sha}" != "${EXPECTED_RELEASE_SHA}"' in publish
    assert publish.index("git/ref/tags/${GITHUB_REF_NAME}") < publish.index("gh release create")


def test_oidc_signing_is_tag_only_and_environment_protected() -> None:
    release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert 'check_version_matches_tag.py "${release_tag}" --require-stable' in release_workflow

    for workflow_name, verify_header in (
        ("release.yml", "  verify-signatures:\n"),
        ("evidence.yml", "  verify:\n"),
    ):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        sign = workflow.split("  sign:\n", maxsplit=1)[1].split(
            verify_header,
            maxsplit=1,
        )[0]

        assert "startsWith(github.ref, 'refs/tags/v')" in sign
        assert "environment:\n      name: signing" in sign
    assert "Validate immutable signing source" in (
        ROOT / ".github" / "workflows" / "evidence.yml"
    ).read_text(encoding="utf-8")


def test_security_monitoring_is_repository_declared_and_sha_pinned() -> None:
    workflow = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    parsed_workflow = yaml.safe_load(workflow)

    assert "github/codeql-action/init@95e58e9a2cdfd71adc6e0353d5c52f41a045d225" in workflow
    assert "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294" in workflow
    assert "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266" in workflow
    job = parsed_workflow["jobs"]["dependency-audit"]
    assert job["runs-on"] == "${{ matrix.os }}"
    assert job["permissions"] == {"contents": "read"}
    assert job["strategy"] == {
        "fail-fast": False,
        "matrix": {
            "os": ["ubuntu-24.04", "windows-2025"],
            "python-version": ["3.11", "3.14"],
        },
    }
    for event_name in ("push", "schedule", "workflow_dispatch"):
        assert f"github.event_name == '{event_name}'" in job["if"]
    checkout = next(
        step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {"persist-credentials": False}
    setup = next(
        step
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("actions/setup-python@")
    )
    assert setup["with"]["python-version"] == "${{ matrix.python-version }}"
    expected_locks = {
        "requirements.lock",
        "requirements-min.lock",
        "requirements-langgraph.lock",
        "requirements-adk.lock",
        "requirements-otel.lock",
    }
    audit_steps = [
        step
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("pypa/gh-action-pip-audit@")
    ]
    assert {step["with"]["inputs"] for step in audit_steps} == expected_locks
    assert len(audit_steps) == len(expected_locks)
    for step in audit_steps:
        assert step["uses"] == ("pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266")
        assert step["with"]["require-hashes"] is True
        assert step["with"]["no-deps"] is True
        assert "continue-on-error" not in step
    assert "disable-pip" not in workflow
    assert (ROOT / ".github" / "dependabot.yml").is_file()


def test_security_workflow_scans_the_exact_source_built_release_payload() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["release-payload-credential-scan"]

    assert job["permissions"] == {"contents": "read"}
    checkout = next(
        step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    commands = "\n".join(str(step.get("run", "")) for step in job["steps"])
    assert "python -m build --no-isolation" in commands
    assert "python scripts/check_wheel_contents.py --dist dist" in commands
    assert "status --porcelain=v1 --untracked-files=all" in commands


def test_security_workflow_scans_complete_history_with_digest_pinned_gitleaks() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    job = workflow["jobs"]["repository-history-secret-scan"]

    trigger_block = workflow_text.split("permissions:", maxsplit=1)[0]
    assert "push:\n    branches:\n      - main" in trigger_block
    assert "paths-ignore:" not in trigger_block
    assert job["permissions"] == {"contents": "read"}
    assert 0 < job["timeout-minutes"] <= 30
    checkout = next(
        step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    commands = "\n".join(str(step.get("run", "")) for step in job["steps"])
    assert (
        "ghcr.io/gitleaks/gitleaks:v8.30.1@"
        "sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb"
    ) in commands
    assert "--platform linux/amd64" in commands
    assert "target=/repo,readonly" in commands
    assert "--gitleaks-ignore-path=/repo/.gitleaksignore" in commands
    log_opts = '--log-opts="--no-textconv --full-history --all --diff-merges=first-parent"'
    assert commands.count(log_opts) == 2
    assert "--diff-filter=tuxdb" not in commands
    assert "--redact" in commands
    assert commands.count("--exit-code=23") == 2
    assert "git rev-list --count --all" in commands
    assert "git log --format='%H' --no-textconv --full-history --all" in commands
    assert "--diff-merges=first-parent --diff-filter=d --no-patch" in commands
    assert "git fsck --strict --no-dangling" in commands
    assert "reachable_commits" in commands
    assert "expected_scan_units" in commands
    assert "unique_scan_units" in commands
    assert "grep -Evq '^[0-9a-f]{40}$'" in commands
    assert 'sort -u "${expected_units_log}"' in commands
    assert "commits scanned\\." in commands
    assert "scanned_units" in commands
    assert '"${scanned_units}" -ne "${expected_scan_units}"' in commands
    assert "stderr is not empty" in commands
    assert "Gitleaks reported an internal Git/scanner error" in commands
    assert "Gitleaks did not prove that it scanned a nonzero commit history" in commands
    assert "gitleaks merge-result detection canary" in commands
    assert "merge --quiet --no-ff --no-commit canary-right" in commands
    assert "cat-file -p HEAD" in commands
    assert "did not produce a merge commit" in commands
    assert "canary_status" in commands
    assert "canary_status}" in commands
    assert "-ne 23" in commands
    canary_prefix = "ghp_"
    canary_body = "wA9mK2pLxN4vRtQzY6bC8dEfGhJlM0oPq1rS"
    assert canary_prefix + canary_body not in commands
    assert "printf '%s%s\\n' 'ghp_' 'wA9mK2pLxN4vRtQzY6bC8dEfGhJlM0oPq1rS'" in commands
    assert commands.count('--user "$(id -u):$(id -g)"') == 2
    assert commands.count("--network none --read-only --cap-drop ALL") == 2
    assert commands.count("--security-opt no-new-privileges") == 2
    assert commands.count("--env HOME=/tmp") == 2
    assert commands.count("--tmpfs /tmp:rw,noexec,nosuid,size=64m") == 2

    ignored = tuple(
        line
        for line in (ROOT / ".gitleaksignore").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert len(ignored) == len(set(ignored))
    assert all(len(fingerprint.split(":")) >= 4 for fingerprint in ignored)


def test_publication_security_jobs_bind_exact_source_artifacts_and_every_release_lock() -> None:
    for workflow_name, artifact_output, artifact_path in (
        ("release.yml", "bundle_artifact_id", ".tmp/security-release"),
        ("publish-testpypi.yml", "distributions_artifact_id", ".tmp/security-dist"),
    ):
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        )
        job = workflow["jobs"]["candidate-security"]

        assert job["needs"] == "build"
        assert job["permissions"] == {"contents": "read"}
        checkout = next(
            step
            for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        )
        assert checkout["with"]["ref"] == "${{ needs.build.outputs.source_sha }}"
        assert checkout["with"]["persist-credentials"] is False
        download = next(
            step
            for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/download-artifact@")
        )
        assert download["with"]["artifact-ids"] == (
            f"${{{{ needs.build.outputs.{artifact_output} }}}}"
        )
        assert download["with"]["path"] == artifact_path
        assert download["with"]["merge-multiple"] is True
        commands = "\n".join(str(step.get("run", "")) for step in job["steps"])
        assert 'test "$(git rev-parse HEAD)" = "${EXPECTED_SOURCE_SHA}"' in commands
        assert "check_wheel_contents.py --dist" in commands
        audit_inputs = {
            step["with"]["inputs"]
            for step in job["steps"]
            if str(step.get("uses", "")).startswith("pypa/gh-action-pip-audit@")
        }
        assert audit_inputs == {
            "requirements.lock",
            "requirements-min.lock",
            "requirements-langgraph.lock",
            "requirements-adk.lock",
            "requirements-otel.lock",
        }
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("pypa/gh-action-pip-audit@"):
                assert step["uses"] == (
                    "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266"
                )
                assert step["with"]["require-hashes"] is True
                assert step["with"]["no-deps"] is True
                assert "continue-on-error" not in step


def test_publication_candidate_qualification_is_sha_bound_and_cross_platform() -> None:
    expected_locks = {
        "requirements.lock",
        "requirements-min.lock",
        "requirements-langgraph.lock",
        "requirements-adk.lock",
        "requirements-otel.lock",
    }
    expected_action = "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266"

    for workflow_name in ("release.yml", "publish-testpypi.yml"):
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        )

        lower = workflow["jobs"]["candidate-lower-bounds"]
        assert lower["needs"] == "build"
        assert lower["runs-on"] == "ubuntu-24.04"
        assert 120 <= lower["timeout-minutes"] <= 180
        assert lower["permissions"] == {"contents": "read"}
        assert lower["strategy"] == {
            "fail-fast": False,
            "matrix": {"python-version": ["3.11", "3.14"]},
        }
        assert "continue-on-error" not in lower
        lower_checkout = next(
            step
            for step in lower["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        )
        assert lower_checkout["with"] == {
            "persist-credentials": False,
            "ref": "${{ needs.build.outputs.source_sha }}",
        }
        lower_setup = next(
            step
            for step in lower["steps"]
            if str(step.get("uses", "")).startswith("actions/setup-python@")
        )
        assert lower_setup["with"]["python-version"] == "${{ matrix.python-version }}"
        lower_commands = "\n".join(str(step.get("run", "")) for step in lower["steps"])
        assert 'test "$(git rev-parse HEAD)" = "${EXPECTED_SOURCE_SHA}"' in lower_commands
        assert "python -m pip install --require-hashes -r requirements-min.lock" in lower_commands
        assert "python -m pip install --no-deps --no-build-isolation ." in lower_commands
        assert "--verify-installed-minimums" in lower_commands
        assert "python -m pip check" in lower_commands
        assert "python -m pytest -q -p no:cacheprovider" in lower_commands
        assert not any("continue-on-error" in step for step in lower["steps"])

        platform = workflow["jobs"]["candidate-platform-audit"]
        assert platform["needs"] == "build"
        assert platform["runs-on"] == "${{ matrix.os }}"
        assert platform["permissions"] == {"contents": "read"}
        assert platform["strategy"] == {
            "fail-fast": False,
            "matrix": {
                "os": ["ubuntu-24.04", "windows-2025"],
                "python-version": ["3.11", "3.14"],
            },
        }
        assert "continue-on-error" not in platform
        platform_checkout = next(
            step
            for step in platform["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        )
        assert platform_checkout["with"] == {
            "persist-credentials": False,
            "ref": "${{ needs.build.outputs.source_sha }}",
        }
        platform_setup = next(
            step
            for step in platform["steps"]
            if str(step.get("uses", "")).startswith("actions/setup-python@")
        )
        assert platform_setup["with"]["python-version"] == "${{ matrix.python-version }}"
        platform_commands = "\n".join(str(step.get("run", "")) for step in platform["steps"])
        assert 'test "$(git rev-parse HEAD)" = "${EXPECTED_SOURCE_SHA}"' in platform_commands
        platform_audits = [
            step for step in platform["steps"] if step.get("uses") == expected_action
        ]
        assert {step["with"]["inputs"] for step in platform_audits} == expected_locks
        assert len(platform_audits) == len(expected_locks)
        for step in platform_audits:
            assert step["with"]["require-hashes"] is True
            assert step["with"]["no-deps"] is True
            assert "continue-on-error" not in step


def test_publication_dags_require_every_candidate_gate_before_privilege() -> None:
    required_gates = [
        "build",
        "reproduce",
        "candidate-security",
        "candidate-lower-bounds",
        "candidate-platform-audit",
    ]

    release = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    for job_name in (
        "prepare-release-tag",
        "resume-release-tag",
        "verify-release-tag-provenance",
    ):
        job = release["jobs"][job_name]
        assert job["needs"] == required_gates
        for gate in required_gates:
            assert f"needs.{gate}.result == 'success'" in job["if"]
    assert release["jobs"]["sign"]["needs"] == ["reproduce", "verify-release-tag-provenance"]
    assert release["jobs"]["pypi-publish"]["permissions"] == {"id-token": "write"}

    testpypi = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "publish-testpypi.yml").read_text(encoding="utf-8")
    )
    publish = testpypi["jobs"]["testpypi-publish"]
    assert publish["needs"] == required_gates
    assert publish["permissions"] == {"id-token": "write"}
    assert "continue-on-error" not in publish


def test_every_workflow_job_has_a_finite_timeout() -> None:
    workflow_root = ROOT / ".github" / "workflows"
    for workflow_path in sorted(workflow_root.glob("*.yml")):
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        for job_name, job in workflow.get("jobs", {}).items():
            timeout = job.get("timeout-minutes")
            assert isinstance(timeout, int) and 0 < timeout <= 360, (
                workflow_path.name,
                job_name,
            )


def test_composite_action_requires_explicit_report_upload_consent() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )

    assert "upload-full-artifacts:" in action
    report_input = action.split("  upload-reports:\n", maxsplit=1)[1].split(
        "  upload-full-artifacts:\n", maxsplit=1
    )[0]
    assert 'default: "false"' in report_input
    assert "Opt in to uploading" in report_input
    full_input = action.split("  upload-full-artifacts:\n", maxsplit=1)[1].split(
        "  retention-days:\n", maxsplit=1
    )[0]
    assert 'default: "false"' in full_input
    minimal = action.split("    - name: Upload minimal reports\n", maxsplit=1)[1].split(
        "    - name: Upload full assurance artifacts\n", maxsplit=1
    )[0]
    assert "evidence-packet.json" in minimal
    assert ("${{ steps.prepare.outputs.out_dir }}/reports/assurance-evidence-graph.json") in minimal
    assert "release-artifact-manifest.json" in minimal
    assert "baseline.runset.json" not in minimal
    assert "path: ${{ inputs.out-dir }}" not in minimal
    assert "retention-days: ${{ inputs.retention-days }}" in minimal


def test_composite_action_confines_outputs_to_workspace_or_runner_temp() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )
    prepare = action.split(
        "    - name: Prepare output directory\n",
        maxsplit=1,
    )[1].split("    - name: Compile suite\n", maxsplit=1)[0]

    assert 'python "${GITHUB_ACTION_PATH}/validate_output_path.py"' in prepare
    assert '--allowed-root "${GITHUB_WORKSPACE}"' in prepare
    assert '--allowed-root "${RUNNER_TEMP}"' in prepare
    assert "validate_workspace_output_path" in prepare
    assert "strict efficacy mode requires an output directory below GITHUB_WORKSPACE" in prepare
    assert ")' +" not in prepare
    assert "must be below the workspace or runner temp root" in prepare
    assert "output directory escaped its approved root" in prepare
    assert prepare.index("mkdir -p") < prepare.rindex("validate_output_path")


def test_composite_action_binds_the_installed_cli_to_its_release_version() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    expected_version = project["project"]["version"]
    verify = action.split(
        "    - name: Verify action and CLI version binding\n",
        maxsplit=1,
    )[1].split("    - name: Validate assurance profile\n", maxsplit=1)[0]

    assert f'AGENT_ASSURE_ACTION_EXPECTED_VERSION: "{expected_version}"' in verify
    assert "AGENT_ASSURE_ACTION_REF: ${{ github.action_ref }}" in verify
    assert 'installed_version="$(agent-assure --version)"' in verify
    assert '[ "${installed_version}" != "${AGENT_ASSURE_ACTION_EXPECTED_VERSION}" ]' in verify
    assert (
        '[ "${AGENT_ASSURE_ACTION_REF}" != "v${AGENT_ASSURE_ACTION_EXPECTED_VERSION}" ]'
    ) in verify


def test_composite_action_requires_one_explicit_efficacy_profile() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )

    migration_input = action.split(
        "  allow-missing-efficacy-for-migration:\n",
        maxsplit=1,
    )[1].split("  upload-name:\n", maxsplit=1)[0]
    profile = action.split("    - name: Validate assurance profile\n", maxsplit=1)[1].split(
        "    - name: Prepare output directory\n",
        maxsplit=1,
    )[0]
    evaluate = action.split("    - name: Evaluate and assemble base packet\n", maxsplit=1)[1].split(
        "    - name: Build and strictly gate efficacy-bearing packet\n",
        maxsplit=1,
    )[0]
    strict = action.split(
        "    - name: Build and strictly gate efficacy-bearing packet\n", maxsplit=1
    )[1].split(
        "    - name: Upload minimal reports\n",
        maxsplit=1,
    )[0]

    assert 'default: "false"' in migration_input
    assert "non-assurance migration profile" in migration_input
    assert (
        "AGENT_ASSURE_ACTION_ALLOW_MISSING_EFFICACY: "
        "${{ inputs.allow-missing-efficacy-for-migration }}"
    ) in profile
    assert "true|false) ;;" in profile
    validation_messages = (
        "allow-missing-efficacy-for-migration must be true or false",
        "control-efficacy-report and efficacy-policy must be provided together",
        "strict efficacy inputs cannot be combined",
        "explicitly select the non-assurance migration profile",
    )
    for message in validation_messages:
        assert message in profile
        assert action.count(message) == 1
        assert message not in evaluate
    # The base CI transaction must be allowed to produce its efficacy-free
    # intermediate packet. Assurance mode immediately replaces and strictly
    # re-gates that packet in the following step.
    assert "--allow-missing-efficacy-for-migration" in evaluate
    assert "--fail-on-warn" in evaluate
    assert "if: inputs.control-efficacy-report != '' && inputs.efficacy-policy != ''" in strict
    assert "agent-assure packet build" in strict
    assert '--control-efficacy "${AGENT_ASSURE_ACTION_CONTROL_EFFICACY_REPORT}"' in strict
    assert '--efficacy-config "${AGENT_ASSURE_ACTION_EFFICACY_POLICY}"' in strict
    assert "agent-assure ci gate" in strict
    assert '--efficacy-policy "${AGENT_ASSURE_ACTION_EFFICACY_POLICY}"' in strict
    assert "--require-efficacy" in strict
    assert "--fail-on-warn" in strict
    assert "--fail-on-not-evaluated" in strict


def test_composite_action_validates_profile_before_output_or_execution_side_effects() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )

    profile_index = action.index("    - name: Validate assurance profile\n")
    prepare_index = action.index("    - name: Prepare output directory\n")
    compile_index = action.index("    - name: Compile suite\n")
    profile = action[profile_index:prepare_index]

    assert profile_index < prepare_index < compile_index
    assert "mkdir -p" not in profile
    assert "rm -f" not in profile
    assert "agent-assure suite compile" not in profile
    assert "agent-assure suite run" not in profile
    assert profile_index < action.index("mkdir -p", prepare_index)
    assert profile_index < action.index("rm -f", prepare_index)
    assert profile_index < action.index("agent-assure suite compile", compile_index)
    assert profile_index < action.index("agent-assure suite run", compile_index)


def test_composite_action_strict_efficacy_inputs_are_rooted_and_not_expression_executed() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )
    prepare = action.split("    - name: Prepare output directory\n", maxsplit=1)[1].split(
        "    - name: Compile suite\n", maxsplit=1
    )[0]
    strict = action.split(
        "    - name: Build and strictly gate efficacy-bearing packet\n", maxsplit=1
    )[1].split("    - name: Upload minimal reports\n", maxsplit=1)[0]

    assert "AGENT_ASSURE_ACTION_CONTROL_EFFICACY_REPORT: ${{ inputs.control-efficacy-report }}" in (
        prepare
    )
    assert "AGENT_ASSURE_ACTION_EFFICACY_POLICY: ${{ inputs.efficacy-policy }}" in prepare
    assert prepare.count("${AGENT_ASSURE_ACTION_CONTROL_EFFICACY_REPORT}") >= 2
    assert prepare.count("${AGENT_ASSURE_ACTION_EFFICACY_POLICY}") >= 2
    assert '--project-root "${GITHUB_WORKSPACE}"' in strict
    assert '--artifact-root "${GITHUB_WORKSPACE}"' in strict
    assert "${{ inputs.control-efficacy-report }}" not in strict.split("run: |", maxsplit=1)[1]
    assert "${{ inputs.efficacy-policy }}" not in strict.split("run: |", maxsplit=1)[1]


def test_composite_action_refuses_root_and_linked_output_directories() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )

    assert 'python "${GITHUB_ACTION_PATH}/validate_output_path.py"' in action
    reports_check = 'validate_output_path "${AGENT_ASSURE_ACTION_OUT_DIR}/reports"'
    assert action.count(reports_check) == 2
    assert "agent-assure refuses an unsafe reports output directory" in action
    assert "agent-assure reports directory escaped its approved root" in action


def test_composite_action_rejects_multiline_output_before_always_uploads() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )
    prepare_index = action.index("    - name: Prepare output directory\n")
    compile_index = action.index("    - name: Compile suite\n")
    upload_index = action.index("    - name: Upload minimal reports\n")
    prepare = action[prepare_index:compile_index]
    uploads = action[upload_index:]

    assert "      id: prepare\n" in prepare
    assert "*$'\\r'*|*$'\\n'*)" in prepare
    assert "agent-assure refuses input paths containing CR or LF" in prepare
    assert "printf 'out_dir=%s\\n'" in prepare
    assert prepare_index < upload_index
    assert uploads.count("steps.prepare.outcome == 'success'") == 2
    assert "${{ inputs.out-dir }}/" not in uploads
    assert "${{ steps.prepare.outputs.out_dir }}/reports/evidence-packet.json" in uploads
    assert "${{ steps.prepare.outputs.out_dir }}/suite.compiled.json" in uploads


def test_composite_action_full_upload_is_an_explicit_artifact_whitelist() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )
    full = action.split(
        "    - name: Upload full assurance artifacts\n",
        maxsplit=1,
    )[1]

    assert "path: ${{ inputs.out-dir }}" not in full
    assert "${{ steps.prepare.outputs.out_dir }}/suite.compiled.json" in full
    assert "${{ steps.prepare.outputs.out_dir }}/candidate.runset.json" in full
    assert "${{ steps.prepare.outputs.out_dir }}/reports/evaluation-report.json" in full
    assert ("${{ steps.prepare.outputs.out_dir }}/reports/assurance-evidence-graph.json") in full


def test_composite_action_clears_owned_outputs_before_any_producer_runs() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )

    prepare_index = action.index("    - name: Prepare output directory\n")
    compile_index = action.index("    - name: Compile suite\n")
    prepare = action[prepare_index:compile_index]

    assert prepare_index < compile_index
    assert "baseline.runset.json" in prepare
    assert "comparison-summary.json" in prepare
    assert "ci-diagnostics.json" in prepare
    assert "refuses an unsafe reports output directory" in prepare
    assert "reports directory escaped its approved root" in prepare
    assert "realpath" not in prepare
    assert "os.path.normcase(os.path.abspath(sys.argv[1]))" in prepare
    assert 'canonical_path "${source_input}"' in prepare
    assert "input aliases an owned output path" in prepare
