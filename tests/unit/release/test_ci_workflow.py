from __future__ import annotations

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

    assert "runs-on: windows-latest" in job
    assert 'python-version: ["3.11", "3.14"]' in job
    assert "tests/unit/runner" in job
    assert "tests/unit/test_rooted_io.py" in job
    assert job.count("python -m pytest") == 2
    assert job.count("--fail-on-skip") == 1
    assert "test_rooted_read_rejects_linked_parent_escape" in job
    assert "test_rooted_directory_lease_blocks_lexical_rename_until_close" in job
    assert "test_external_script_timeout_terminates_descendant_process_tree" in job
    assert "test_post_spawn_validation_failure_terminates_and_reaps_suspended_process" in job
    assert "test_windows_external_script_success_kills_descendant_when_job_closes" in job
    assert "make release-check" not in job


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

    assert workflow.count("fetch-depth: 0") == 2
    assert (
        workflow.count("python scripts/check_tagged_schema_immutability.py --require-release-tags")
        == 2
    )
    assert workflow.count('make release-check EXPECTED_RELEASE="${EXPECTED_VERSION}"') == 1
    assert 'make release-check EXPECTED_RELEASE="${EXPECTED_RELEASE}"' in workflow


def test_every_checkout_disables_persisted_credentials() -> None:
    workflows = tuple((ROOT / ".github" / "workflows").glob("*.yml"))
    for path in workflows:
        workflow = path.read_text(encoding="utf-8")
        assert workflow.count("persist-credentials: false") == workflow.count(
            "uses: actions/checkout@"
        ), path.name


def test_artifact_id_downloads_merge_into_the_exact_requested_path() -> None:
    expected_downloads = {
        "release.yml": 11,
        "publish-testpypi.yml": 2,
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
        "verified_signed_bundle_artifact_id": (
            "${{ steps.verify-uploaded.outputs.verified_signed_bundle_artifact_id }}"
        ),
    }
    assert all("continue-on-error" not in step for step in fresh["steps"])
    assert not any(
        str(step.get("uses", "")).startswith("actions/upload-artifact@") for step in fresh["steps"]
    )
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

    validation = fresh["steps"][-1]
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

    github_release = jobs["github-release"]
    assert github_release["needs"] == "verify-uploaded-artifacts"
    assert github_release["steps"][0]["with"]["artifact-ids"] == (
        "${{ needs.verify-uploaded-artifacts.outputs.verified_signed_bundle_artifact_id }}"
    )
    pypi = jobs["pypi-publish"]
    assert pypi["needs"] == ["verify-uploaded-artifacts", "github-release"]
    assert pypi["steps"][0]["with"]["artifact-ids"] == (
        "${{ needs.verify-uploaded-artifacts.outputs.distributions_artifact_id }}"
    )


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
    reproduce = workflow.split("  reproduce:\n", maxsplit=1)[1].split("  sign:\n", maxsplit=1)[0]
    sign = workflow.split("  sign:\n", maxsplit=1)[1].split("  verify-signatures:\n", maxsplit=1)[0]
    pypi = workflow.split("  pypi-publish:\n", maxsplit=1)[1].split(
        "  recover-verify:\n", maxsplit=1
    )[0]

    assert "id-token: write" not in build
    assert "contents: write" not in build
    assert "id-token: write" not in reproduce
    assert "id-token: write" in sign
    assert "actions/checkout" not in sign
    assert "setup-python" not in sign
    assert "pip install" not in sign
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
    recover_verify = workflow.split("  recover-verify:\n", maxsplit=1)[1].split(
        "  recover-github-release:\n", maxsplit=1
    )[0]
    recover_release = workflow.split("  recover-github-release:\n", maxsplit=1)[1].split(
        "  recover-pypi-publish:\n", maxsplit=1
    )[0]
    recover_pypi = workflow.split("  recover-pypi-publish:\n", maxsplit=1)[1]

    assert "recover-v0.6.0" in workflow
    assert (
        "if: github.event_name != 'workflow_dispatch' || inputs.operation == 'standard'"
    ) in workflow
    assert (
        "if: github.event_name == 'workflow_dispatch' && inputs.operation == 'recover-v0.6.0'"
    ) in recover_verify
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


def test_release_requires_reproduction_before_signing_and_publication() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "needs: [verify-uploaded-artifacts, github-release]" in workflow
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
        assert "needs: reproduce" in sign
        assert "artifact-ids: ${{ needs.reproduce.outputs.verified_bundle_artifact_id }}" in sign
        assert "needs.build.outputs.bundle_artifact_id" not in sign


def test_github_release_consumes_only_freshly_verified_uploaded_artifact() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    publish = workflow.split("  github-release:\n", maxsplit=1)[1].split(
        "  pypi-publish:\n", maxsplit=1
    )[0]

    assert "needs: verify-uploaded-artifacts" in publish
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
    assert 'check_version_matches_tag.py "${GITHUB_REF_NAME}" --require-stable' in release_workflow

    for workflow_name, verify_header in (
        ("release.yml", "  verify-signatures:\n"),
        ("evidence.yml", "  verify:\n"),
    ):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        sign = workflow.split("  sign:\n", maxsplit=1)[1].split(
            verify_header,
            maxsplit=1,
        )[0]

        assert "if: startsWith(github.ref, 'refs/tags/v')" in sign
        assert "environment:\n      name: signing" in sign
    assert "Validate immutable signing source" in (
        ROOT / ".github" / "workflows" / "evidence.yml"
    ).read_text(encoding="utf-8")


def test_security_monitoring_is_repository_declared_and_sha_pinned() -> None:
    workflow = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")

    assert "github/codeql-action/init@95e58e9a2cdfd71adc6e0353d5c52f41a045d225" in workflow
    assert "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294" in workflow
    assert "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266" in workflow
    audit = workflow.split("  dependency-audit:\n", maxsplit=1)[1].split("  codeql:\n", maxsplit=1)[
        0
    ]
    assert "github.event_name == 'push'" in audit
    for lockfile in (
        "requirements.lock",
        "requirements-langgraph.lock",
        "requirements-adk.lock",
        "requirements-otel.lock",
    ):
        assert f"          - {lockfile}" in audit
    assert "inputs: ${{ matrix.lockfile }}" in audit
    assert "require-hashes: true" in audit
    assert "no-deps: true" in audit
    assert "disable-pip" not in audit
    assert (ROOT / ".github" / "dependabot.yml").is_file()


def test_composite_action_uploads_minimal_reports_by_default() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )

    assert "upload-full-artifacts:" in action
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


def test_composite_action_refuses_root_and_linked_output_directories() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )

    assert 'if [ "${canonical_out_dir}" = "/" ]; then' in action
    assert 'if [ -L "${AGENT_ASSURE_ACTION_OUT_DIR}/reports" ]; then' in action
    assert "agent-assure refuses linked output directories" in action


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
    assert "agent-assure refuses output directories containing CR or LF" in prepare
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
    assert "refuses linked output directories" in prepare
    assert 'realpath -m -- "${source_input}"' in prepare
    assert "input aliases an owned output path" in prepare
