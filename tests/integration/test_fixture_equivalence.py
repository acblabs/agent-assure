from __future__ import annotations

from pathlib import Path

from agent_assure.authoring.compiler import compile_suite
from agent_assure.fixtures.manifest import build_fixture_manifest, fixture_manifest_digest
from agent_assure.runner.fixture_runner import load_variant_config, run_suite

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
VARIANTS = (
    Path("examples/prior_auth_synthetic/variants/baseline.yaml"),
    Path("examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"),
    Path("examples/prior_auth_synthetic/variants/candidate_provider_policy.yaml"),
    Path("examples/prior_auth_synthetic/variants/candidate_smoke_fail.yaml"),
)


def test_prior_auth_variants_share_identical_fixture_manifest() -> None:
    compiled = compile_suite(SUITE)
    manifest_digest = fixture_manifest_digest(build_fixture_manifest(compiled, SUITE.parent))
    runsets = [
        run_suite(compiled, load_variant_config(variant), SUITE.parent)
        for variant in VARIANTS
    ]
    observed = {
        run.provenance.fixture_manifest_digest
        for runset in runsets
        for run in runset.runs
    }
    assert observed == {manifest_digest}
