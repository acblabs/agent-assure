from __future__ import annotations

# Paths are relative to their respective agent_assure.examples resource roots.
# Keep the release archive check and installed-package smoke assertion on one
# inventory so a required control cannot be shipped by one gate and omitted by
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

PROCESS_EQUIVALENCE_BENCHMARK_REQUIRED_RESOURCE_PATHS = (
    "__init__.py",
    "README.md",
    "authority-contract.json",
    "benchmark.json",
    *(
        resource
        for index in range(1, 169)
        for arm in ("baseline", "counterfactual")
        for resource in (
            f"corpora/synthetic-benefit-eligibility-{index:03d}/{arm}/corpus-manifest.json",
            f"corpora/synthetic-benefit-eligibility-{index:03d}/{arm}/governing-policy.json",
        )
    ),
    *(f"inputs/synthetic-benefit-eligibility-{index:03d}.json" for index in range(1, 169)),
    *(
        f"knowledge-contracts/{contract_id}.json"
        for contract_id in (
            "approve-invariant-v1",
            "approve-to-deny-v1",
            "deny-invariant-v1",
            "deny-to-approve-v1",
        )
    ),
)

__all__ = [
    "EVIDENCE_SENSITIVITY_REQUIRED_RESOURCE_PATHS",
    "PROCESS_EQUIVALENCE_BENCHMARK_REQUIRED_RESOURCE_PATHS",
]
