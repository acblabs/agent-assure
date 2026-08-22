from __future__ import annotations

# Paths are relative to ``agent_assure.examples/evidence_sensitivity``. Keep the
# release archive check and installed-package smoke assertion on one inventory so
# a newly required detector control cannot be shipped by one gate and omitted by
# the other.
EVIDENCE_SENSITIVITY_REQUIRED_RESOURCE_PATHS = (
    "README.md",
    "responsive_suite.yaml",
    "evidence_inertial_suite.yaml",
    "evidence_reversed_suite.yaml",
    "knowledge-contract.yaml",
    "corpora/policy_a/corpus-manifest.json",
    "corpora/policy_a/governing-policy.json",
    "corpora/policy_b/corpus-manifest.json",
    "corpora/policy_b/governing-policy.json",
    "fixtures/responsive/requests/synthetic-benefit-eligibility.json",
    "fixtures/responsive/model_outputs/synthetic-benefit-eligibility.json",
    "fixtures/responsive/tool_outputs/synthetic-benefit-eligibility.json",
    "fixtures/evidence_inertial/requests/synthetic-benefit-eligibility.json",
    "fixtures/evidence_inertial/model_outputs/synthetic-benefit-eligibility.json",
    "fixtures/evidence_inertial/tool_outputs/synthetic-benefit-eligibility.json",
    "fixtures/evidence_reversed/requests/synthetic-benefit-eligibility.json",
    "fixtures/evidence_reversed/model_outputs/synthetic-benefit-eligibility.json",
    "fixtures/evidence_reversed/tool_outputs/synthetic-benefit-eligibility.json",
)


__all__ = ["EVIDENCE_SENSITIVITY_REQUIRED_RESOURCE_PATHS"]
