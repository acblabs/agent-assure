from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CAPTURE = ROOT / ".github" / "workflows" / "external-pilot-capture.yml"
FINALIZE = ROOT / ".github" / "workflows" / "external-pilot-finalize.yml"
KIT = ROOT / "src" / "agent_assure" / "external_pilot_kit.py"
CI_WORKFLOWS = tuple(
    ROOT / ".github" / "workflows" / name for name in ("ci.yml", "docs.yml", "security.yml")
)
VOLUNTEER_ISSUE = ROOT / "docs" / "templates" / "external_pilot_volunteer_issue.md"
REVIEW_TEMPLATE = ROOT / "docs" / "templates" / "external_pilot_independence_review.yaml"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
ZERO_REVISION = "0" * 40
UPSTREAM_REF = re.compile(r"repository: acblabs/agent-assure\n\s+ref: ([0-9a-f]{40})")
PINNED_ACTIONS = {
    "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
}


def _upstream_revision(workflow: str) -> str:
    match = UPSTREAM_REF.search(workflow)
    assert match is not None
    return match.group(1)


def _uploaded_paths(workflow: str, directory: str) -> tuple[str, ...]:
    prefix = f"${{{{ runner.temp }}}}/{directory}/"
    return tuple(line.strip() for line in workflow.splitlines() if line.strip().startswith(prefix))


def test_external_pilot_workflows_are_manual_least_privilege_and_use_only_automatic_token() -> None:
    capture = CAPTURE.read_text(encoding="utf-8")
    finalize = FINALIZE.read_text(encoding="utf-8")

    for workflow in (capture, finalize):
        assert "workflow_dispatch:" in workflow
        assert "pull_request:" not in workflow
        assert "push:" not in workflow
        assert "id-token: write" not in workflow
        assert "contents: write" not in workflow
        assert "${{ secrets." not in workflow
        assert "github.event.repository.parent" not in workflow
        assert "github.event.repository.fork" not in workflow
        assert "GH_TOKEN: ${{ github.token }}" in workflow
        assert "gh api \\" in workflow
        assert "| jq -e \\" in workflow
        assert ">/dev/null" in workflow
        assert '(.fork == true) and (.parent.full_name == "acblabs/agent-assure")' in workflow
        assert "ACTOR: ${{ github.actor }}" in workflow
        assert "TRIGGERING_ACTOR: ${{ github.triggering_actor }}" in workflow
        assert '[[ "${TRIGGERING_ACTOR}" = "${ACTOR}" ]]' in workflow
        assert '[[ "${REPOSITORY_OWNER,,}" != "acblabs" ]]' in workflow
        assert "::error title=External pilot" in workflow
        assert "AGENT_ASSURE_PILOT_PARENT_REPOSITORY: acblabs/agent-assure" in workflow
        assert "runs-on: ubuntu-24.04" in workflow
        assert 'python-version: "3.11.14"' in workflow

    assert "permissions:\n  contents: read" in capture
    assert "permissions:\n  actions: read\n  contents: read" in finalize
    assert capture.count("persist-credentials: false") == capture.count("uses: actions/checkout@")
    assert finalize.count("persist-credentials: false") == finalize.count("uses: actions/checkout@")
    assert "github-token: ${{ github.token }}" in finalize


def test_external_pilot_workflows_pin_actions_and_upload_explicit_inventories() -> None:
    capture = CAPTURE.read_text(encoding="utf-8")
    finalize = FINALIZE.read_text(encoding="utf-8")
    combined = capture + finalize

    for line in combined.splitlines():
        if "uses: actions/" in line:
            specification = line.strip().removeprefix("uses: ")
            action, revision = specification.rsplit("@", maxsplit=1)
            assert action in PINNED_ACTIONS
            assert revision == PINNED_ACTIONS[action]

    capture_paths = (
        "${{ runner.temp }}/external-pilot-capture/external-pilot-capture.json",
        "${{ runner.temp }}/external-pilot-capture/environment-control-evidence.json",
        "${{ runner.temp }}/external-pilot-capture/environment-manifest.json",
        "${{ runner.temp }}/external-pilot-capture/command-execution-evidence.json",
        "${{ runner.temp }}/external-pilot-capture/input-manifest.json",
        "${{ runner.temp }}/external-pilot-capture/${{ steps.distribution.outputs.wheel_name }}",
        "${{ runner.temp }}/external-pilot-capture/assurance-mutation-campaign.json",
    )
    candidate_paths = (
        "${{ runner.temp }}/external-pilot-candidate/environment-control-evidence.json",
        "${{ runner.temp }}/external-pilot-candidate/environment-manifest.json",
        "${{ runner.temp }}/external-pilot-candidate/command-execution-evidence.json",
        "${{ runner.temp }}/external-pilot-candidate/input-manifest.json",
        "${{ runner.temp }}/external-pilot-candidate/${{ steps.distribution.outputs.wheel_name }}",
        "${{ runner.temp }}/external-pilot-candidate/assurance-mutation-campaign.json",
        "${{ runner.temp }}/external-pilot-candidate/friction-assessment.json",
        "${{ runner.temp }}/external-pilot-candidate/remediation-record.json",
        "${{ runner.temp }}/external-pilot-candidate/publication-consent.json",
        "${{ runner.temp }}/external-pilot-candidate/external-pilot-evidence.json",
    )
    assert _uploaded_paths(capture, "external-pilot-capture") == capture_paths
    assert _uploaded_paths(finalize, "external-pilot-candidate") == candidate_paths
    assert all("*" not in path for path in (*capture_paths, *candidate_paths))
    assert "external-pilot-capture.json" not in "\n".join(candidate_paths)
    assert combined.count("include-hidden-files: false") == 2
    assert "participant-waiver.yaml" in combined
    assert (
        "raw"
        not in "\n".join(
            line for line in combined.splitlines() if line.strip().startswith("path:")
        ).casefold()
    )


def test_external_pilot_workflows_fail_closed_until_the_source_commit_is_pinned() -> None:
    capture = CAPTURE.read_text(encoding="utf-8")
    finalize = FINALIZE.read_text(encoding="utf-8")

    capture_revision = _upstream_revision(capture)
    finalize_revision = _upstream_revision(finalize)
    assert capture_revision == finalize_revision == ZERO_REVISION
    for workflow in (capture, finalize):
        assert workflow.count("Refuse an unfinalized execution-source pin") == 1
        assert "External pilot unavailable" in workflow
        assert "Do not recruit or dispatch this workflow." in workflow
        assert workflow.index("Refuse an unfinalized execution-source pin") < workflow.index(
            "uses: actions/"
        )
    assert "ref: main" not in capture
    assert "ref: main" not in finalize


def test_external_pilot_build_epoch_matches_the_release_build_epoch() -> None:
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    capture = CAPTURE.read_text(encoding="utf-8")
    finalize = FINALIZE.read_text(encoding="utf-8")
    epoch = re.search(r'SOURCE_DATE_EPOCH: "([0-9]+)"', release)

    assert epoch is not None
    expected = f'SOURCE_DATE_EPOCH: "{epoch.group(1)}"'
    assert expected in capture
    assert expected in finalize


def test_volunteer_issue_requires_an_immutable_trusted_workflow_revision() -> None:
    issue = VOLUNTEER_ISSUE.read_text(encoding="utf-8")

    assert "blob/main" not in issue
    assert "blob/TRUSTED_WORKFLOW_REVISION/docs/external_pilot_quickstart.md" in issue
    assert "do not post this issue" in issue
    assert "zero execution-source sentinel/refusal step" in issue


def test_pilot_integrity_surfaces_have_precise_codeowners() -> None:
    codeowners = CODEOWNERS.read_text(encoding="utf-8")

    for pattern in (
        "/src/agent_assure/cli/release_cmd.py @acblabs",
        "/src/agent_assure/external_pilot_kit.py @acblabs",
        "/src/agent_assure/pilot_bundle.py @acblabs",
        "/src/agent_assure/schema/pilot.py @acblabs",
        "/docs/external_pilot*.md @acblabs",
        "/docs/templates/external_pilot* @acblabs",
    ):
        assert pattern in codeowners


def test_reviewer_template_requires_deliberate_attestations() -> None:
    template = REVIEW_TEMPLATE.read_text(encoding="utf-8")

    attestation_fields = (
        "manual_approval_is_trust_root",
        "reviewer_independent_of_pilot_execution",
        "environment_control_evidence_reviewed",
        "artifact_inventory_reviewed",
        "tested_distribution_provenance_reviewed",
        "command_input_bindings_reviewed",
        "execution_time_input_content_digests_reviewed",
        "input_semantic_identities_reviewed",
        "complete_bundle_publication_consent_reviewed",
        "workflow_bytes_match_trusted_revision",
        "run_head_shas_reviewed",
        "workflow_run_urls_reviewed",
        "trusted_workflow_bytes_reviewed",
        "execution_source_pins_reviewed",
        "public_workflow_inputs_reviewed",
        "friction_and_remediation_disposition_reviewed",
        "friction_category_and_remediation_bindings_reviewed",
        "privacy_boundary_reviewed",
    )
    for field in attestation_fields:
        assert f"{field}: true" not in template
        assert f"{field}: false" in template
    assert "review_outcome: replace-after-review" in template


def test_pilot_only_pushes_skip_unrelated_jobs_without_weakening_pr_or_schedule() -> None:
    workflows = {path.name: path.read_text(encoding="utf-8") for path in CI_WORKFLOWS}

    for workflow in workflows.values():
        assert 'paths-ignore:\n      - "agent-assure-pilot/**"' in workflow
        assert "pull_request:" in workflow
    assert "schedule:" in workflows["security.yml"]
    assert "workflow_dispatch:" in workflows["security.yml"]


def test_capture_requires_informed_temporary_storage_consent() -> None:
    capture = CAPTURE.read_text(encoding="utf-8")
    finalize = FINALIZE.read_text(encoding="utf-8")

    assert "consent_to_temporary_actions_storage:" in capture
    assert (
        "I consent to 14-day fork Actions storage/read access, linkable CI bindings, "
        "and committed-input digests"
    ) in capture
    assert "Privacy-safe pseudonym" not in capture
    assert "Pseudonym (not your GitHub name; see participant guide)" in capture
    assert (
        "TEMPORARY_STORAGE_CONSENT_GRANTED: ${{ inputs.consent_to_temporary_actions_storage }}"
    ) in capture
    assert '[[ "${TEMPORARY_STORAGE_CONSENT_GRANTED}" = "true" ]]' in capture
    assert "--temporary-storage-consent-granted" in capture
    assert capture.count("retention-days: 14") == 1
    assert (
        "I authorize documented prospective publication, 14-day fork storage/read "
        "access, and input-digest/opaque correlation"
    ) in finalize


def test_finalization_uses_neutral_choices_and_a_bound_applied_remediation_transition() -> None:
    finalize = FINALIZE.read_text(encoding="utf-8")

    assert finalize.count("- select_one_required") == 3
    assert "- not_applicable" in finalize
    assert "remediation_source_revision:" in finalize
    assert "prior_candidate_evidence_digest:" in finalize
    assert "/compare/${EXPECTED_SOURCE_REVISION}...${REMEDIATION_SOURCE_REVISION}" in finalize
    assert '--remediation-disposition "${REMEDIATION_DISPOSITION}"' in finalize
    assert '--remediation-source-revision "${REMEDIATION_SOURCE_REVISION}"' in finalize
    assert '--prior-candidate-evidence-digest "${PRIOR_CANDIDATE_EVIDENCE_DIGEST}"' in finalize


def test_external_pilot_uses_clean_locked_isolated_environments() -> None:
    capture = CAPTURE.read_text(encoding="utf-8")
    finalize = FINALIZE.read_text(encoding="utf-8")

    for workflow in (capture, finalize):
        assert 'python -m venv "${RUNNER_TEMP}/pilot-venv"' in workflow
        assert "--require-hashes" in workflow
        assert "-r agent-assure-source/requirements.lock" in workflow
        assert '"${RUNNER_TEMP}/pilot-venv/bin/python" -m pip install' in workflow
        assert "--no-deps" in workflow
        assert '"${RUNNER_TEMP}/pilot-venv/bin/python" -I \\' in workflow
        assert "python -m agent_assure.external_pilot_kit" not in workflow
        assert workflow.index("python -m venv") < workflow.index("--require-hashes")
        assert workflow.index("--require-hashes") < workflow.index("--no-deps")
        assert workflow.index("--no-deps") < workflow.index(" -I \\")

    assert '"${RUNNER_TEMP}/pilot-venv/bin/python" -m pip wheel' in capture
    assert "--no-build-isolation" in capture
    assert capture.count("--no-deps") == 2
    assert '"${RUNNER_TEMP}/pilot-venv/bin/python" -m pip wheel' in finalize
    assert "--no-build-isolation" in finalize
    assert finalize.count("--no-deps") == 2
    assert (capture + finalize).count("shopt -s nullglob") == 2
    assert '"${trusted_wheels[0]}"' in finalize
    assert '"${captured_wheels[0]}"' not in finalize
    assert finalize.index('"${trusted_wheels[0]}"') < finalize.index(" -I \\")
    assert 'source_revision="$(git -C agent-assure-source rev-parse HEAD)"' in finalize
    assert '--expected-source-revision "${EXPECTED_SOURCE_REVISION}"' in finalize


def test_finalization_download_is_bound_to_the_requested_fork_run() -> None:
    finalize = FINALIZE.read_text(encoding="utf-8")

    assert (
        "name: external-pilot-capture-"
        "${{ inputs.capture_run_id }}-${{ inputs.capture_run_attempt }}"
    ) in finalize
    assert "repository: ${{ github.repository }}" in finalize
    assert "run-id: ${{ inputs.capture_run_id }}" in finalize
    assert "github-token: ${{ github.token }}" in finalize


def test_pilot_kit_records_a_direct_campaign_invocation_and_discards_raw_streams() -> None:
    source = KIT.read_text(encoding="utf-8")

    expected_tokens = (
        '"agent_assure.cli.main"',
        '"controls"',
        '"mutate"',
        '"--catalog"',
        '"core/v1"',
        '"--waiver"',
        '"--out"',
    )
    assert all(token in source for token in expected_tokens)
    assert "stdout=subprocess.DEVNULL" in source
    assert "stderr=subprocess.DEVNULL" in source
    assert "raw_output_persisted=False" in source
    assert 'classification="external"' in source
    assert "qualifies_as_external_attempt=True" in source
    loader = source[
        source.index("def _load_verified_capture") : source.index("def _verify_capture_directory")
    ]
    assert "_validate_running_agent_assure_code_matches_wheel(wheel_bytes)" in loader
    assert "capture.subject.source_revision != expected_source_revision" in source
