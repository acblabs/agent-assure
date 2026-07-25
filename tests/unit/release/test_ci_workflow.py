from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_release_validating_ci_job_fetches_full_history() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    test_job = workflow.split("  test:\n", maxsplit=1)[1].split(
        "  schema-immutability:\n", maxsplit=1
    )[0]

    assert "fetch-depth: 0" in test_job
    assert "make release-check" in test_job


def test_evidence_build_and_reproduction_jobs_fetch_full_history() -> None:
    workflow = (ROOT / ".github" / "workflows" / "evidence.yml").read_text(
        encoding="utf-8"
    )

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
        "from opentelemetry.exporter.otlp.proto.http.trace_exporter import "
        "OTLPSpanExporter"
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
    workflow = (ROOT / ".github" / "workflows" / "publish-testpypi.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("fetch-depth: 0") == 2
    assert (
        workflow.count(
            "python scripts/check_tagged_schema_immutability.py --require-release-tags"
        )
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


def test_release_privileges_are_split_from_build_and_verification() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    build = workflow.split("  build:\n", maxsplit=1)[1].split("  reproduce:\n", maxsplit=1)[0]
    reproduce = workflow.split("  reproduce:\n", maxsplit=1)[1].split(
        "  sign:\n", maxsplit=1
    )[0]
    sign = workflow.split("  sign:\n", maxsplit=1)[1].split(
        "  verify-signatures:\n", maxsplit=1
    )[0]
    pypi = workflow.split("  pypi-publish:\n", maxsplit=1)[1]

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


def test_release_requires_reproduction_before_signing_and_publication() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert "needs: [verify-signatures, github-release]" in workflow
    assert "python scripts/assert_dist_reproducible.py" in workflow
    assert workflow.count("--expected-release") == 2
    assert ".tmp/published\n          .tmp/release" in workflow
    assert "--verified-out .tmp/verified-release" in workflow
    assert "--require-clean-source" in workflow
    assert "--clobber" not in workflow
    assert "gh release create" in workflow
    assert "concurrency:" in workflow


def test_signers_only_consume_reproducer_promoted_artifacts() -> None:
    for workflow_name in ("release.yml", "evidence.yml"):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(
            encoding="utf-8"
        )
        reproduce = workflow.split("  reproduce:\n", maxsplit=1)[1].split(
            "  sign:\n", maxsplit=1
        )[0]
        sign = workflow.split("  sign:\n", maxsplit=1)[1].split(
            "  verify" if workflow_name == "evidence.yml" else "  verify-signatures:\n",
            maxsplit=1,
        )[0]

        assert "verified_bundle_artifact_id:" in reproduce
        assert "path: .tmp/verified-release" in reproduce
        assert "needs: reproduce" in sign
        assert (
            "artifact-ids: ${{ needs.reproduce.outputs.verified_bundle_artifact_id }}"
            in sign
        )
        assert "needs.build.outputs.bundle_artifact_id" not in sign


def test_github_release_consumes_only_signature_verifier_promotion() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    publish = workflow.split("  github-release:\n", maxsplit=1)[1].split(
        "  pypi-publish:\n", maxsplit=1
    )[0]

    assert "needs: verify-signatures" in publish
    assert (
        "artifact-ids: "
        "${{ needs.verify-signatures.outputs.verified_signed_bundle_artifact_id }}"
        in publish
    )
    assert "needs.sign.outputs.signed_bundle_artifact_id" not in publish


def test_github_release_rechecks_remote_tag_against_signed_commit() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    publish = workflow.split("  github-release:\n", maxsplit=1)[1].split(
        "  pypi-publish:\n", maxsplit=1
    )[0]

    assert "EXPECTED_RELEASE_SHA: ${{ github.sha }}" in publish
    assert "git/ref/tags/${GITHUB_REF_NAME}" in publish
    assert "git/tags/${tag_sha}" in publish
    assert '"${tag_sha}" != "${EXPECTED_RELEASE_SHA}"' in publish
    assert publish.index("git/ref/tags/${GITHUB_REF_NAME}") < publish.index(
        "gh release create"
    )


def test_oidc_signing_is_tag_only_and_environment_protected() -> None:
    for workflow_name, verify_header in (
        ("release.yml", "  verify-signatures:\n"),
        ("evidence.yml", "  verify:\n"),
    ):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(
            encoding="utf-8"
        )
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
    workflow = (ROOT / ".github" / "workflows" / "security.yml").read_text(
        encoding="utf-8"
    )

    assert "github/codeql-action/init@95e58e9a2cdfd71adc6e0353d5c52f41a045d225" in workflow
    assert "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294" in workflow
    assert "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266" in workflow
    audit = workflow.split("  dependency-audit:\n", maxsplit=1)[1].split(
        "  codeql:\n", maxsplit=1
    )[0]
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


def test_composite_action_full_upload_is_an_explicit_artifact_whitelist() -> None:
    action = (ROOT / ".github" / "actions" / "agent-assure" / "action.yml").read_text(
        encoding="utf-8"
    )
    full = action.split(
        "    - name: Upload full assurance artifacts\n",
        maxsplit=1,
    )[1]

    assert "path: ${{ inputs.out-dir }}" not in full
    assert "${{ inputs.out-dir }}/suite.compiled.json" in full
    assert "${{ inputs.out-dir }}/candidate.runset.json" in full
    assert "${{ inputs.out-dir }}/reports/evaluation-report.json" in full


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
