# Controlled Evidence Sensitivity

This report is a **synthetic detector contract test**. It measures a declared controlled evidence-response relation; it is not a causal guarantee and does not estimate failure prevalence in real models.

> **Scope limit:** Synthetic declarative fixture harness/oracle only; this result does not show that a model used contextual evidence instead of parametric memory.

## Result

- State: `responsive`
- Gate effect: `pass`
- Verdict-bearing: `true`
- Endpoint: `expected_decision_response`
- Endpoint value: `true`
- Outcome classification: `expected_response_observed`
- Outcome: Expected decisions (baseline -&gt; counterfactual): approve -&gt; deny; observed decisions: approve -&gt; deny. The expected governing-evidence response was observed in both arms.
- Expected relation: `decision_flip`
- Observed relation: `decision_flip`
- Deterministic: `true`
- Detector status: `synthetic_detector_contract_test`
- Subject execution scope: `declarative_fixture_harness_not_model_evidence_use`
- Provenance binding: `fixture_declared_unverified_digests`
- Synthetic data provenance: `bundled_digest_verified`
- Synthetic data attestation digest: `not_applicable`
- Raw content persistence: `exact_corpus_and_fixture_utf8_embedded`
- Claim scope: `controlled_evidence_sensitivity_not_causal_guarantee`
- Population claim: `none_bundled_synthetic_fixture_only`
- Protocol digest: `0e9385a0b814b111832cf541595e8a5232e0e0c71757bde3cb8d98b1b9b3edec`
- Authority contract digest: `9058dfb027d0b7f5f2dcf37d81420ec729fdc4fe753e921fb2f596e6dba2f816`
- Reason codes: none

## Arm Decisions

| Arm | Corpus digest | Retrieval | Governing support | Evidence link | Decision | Expected | Expected match |
| --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | `0764f9224779f6f07877f010ecf455773c7840fe498269830eecdb78b13676fc` | `true` | `true` | `true` | `approve/approved` | `approve/approved` | `true` |
| counterfactual | `7b029a4c7b099d04accb8bf9480008d4d8e01961a39aa1bdb3d92cc5e2626f81` | `true` | `true` | `true` | `deny/denied` | `deny/denied` | `true` |

## Decision-Inertia Finding

- Detected: `false`
- State: `pass`
- Message: Decision inertia was not observed under the declared controlled protocol.

## Controlled-Difference Manifest

`protocol_fixed` rows are structural protocol controls. `arm_observed` rows are derived independently from each corpus arm and carry the discriminating evidence.

| Dimension | Basis | Baseline | Counterfactual | Contract | State |
| --- | --- | --- | --- | --- | --- |
| `agent_implementation_digest` | `protocol_fixed` | `3678ca2dc87bd9ed4306af91b4c7e22e12d8f63044a4544bff10d817fe65965c` | `3678ca2dc87bd9ed4306af91b4c7e22e12d8f63044a4544bff10d817fe65965c` | `equal` | `controlled` |
| `corpus_digest` | `arm_observed` | `0764f9224779f6f07877f010ecf455773c7840fe498269830eecdb78b13676fc` | `7b029a4c7b099d04accb8bf9480008d4d8e01961a39aa1bdb3d92cc5e2626f81` | `different` | `expected_difference` |
| `corpus_document_catalog_digest` | `arm_observed` | `df06ee8bf96869705e857b27659df0029f6e5d6d9984960ff3ca93f134854bcb` | `df06ee8bf96869705e857b27659df0029f6e5d6d9984960ff3ca93f134854bcb` | `equal` | `controlled` |
| `deterministic_subject` | `protocol_fixed` | `true` | `true` | `equal` | `controlled` |
| `fixture_manifest_digest` | `protocol_fixed` | `e93ce6d8258c80fd56f004cbb34a3186fe6ca6b02beddad082e17e18a6d6f359` | `e93ce6d8258c80fd56f004cbb34a3186fe6ca6b02beddad082e17e18a6d6f359` | `equal` | `controlled` |
| `governing_evidence_digest` | `arm_observed` | `39e0ed91e07ef56563b5f2f74422735196e6b7889081c603a3d2f443b895dc13` | `0a11b36c7bc440e7227ae9bc91d3e071fa0c4c06240c1c1c35635f3fd6a7e9f6` | `different` | `expected_difference` |
| `governing_retrieval_identity_digest` | `arm_observed` | `dafa54ea76f884dabf884e1ac39f76763168404201103a0f7b050d3d7d3c22e3` | `dafa54ea76f884dabf884e1ac39f76763168404201103a0f7b050d3d7d3c22e3` | `equal` | `controlled` |
| `knowledge_contract_digest` | `protocol_fixed` | `9058dfb027d0b7f5f2dcf37d81420ec729fdc4fe753e921fb2f596e6dba2f816` | `9058dfb027d0b7f5f2dcf37d81420ec729fdc4fe753e921fb2f596e6dba2f816` | `equal` | `controlled` |
| `model_digest` | `protocol_fixed` | `bc987bc3e4bd9475c7a04887537029f65e0cfafc29511974911eb99582b9be7c` | `bc987bc3e4bd9475c7a04887537029f65e0cfafc29511974911eb99582b9be7c` | `equal` | `controlled` |
| `non_governing_evidence_digest` | `arm_observed` | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` | `equal` | `controlled` |
| `prompt_template_digest` | `protocol_fixed` | `fdcd7641403825e9cfec862b3a47d203c335de53f333ddecc0d7f7bd2ea64ed9` | `fdcd7641403825e9cfec862b3a47d203c335de53f333ddecc0d7f7bd2ea64ed9` | `equal` | `controlled` |
| `producer_version` | `protocol_fixed` | `0.6.5` | `0.6.5` | `equal` | `controlled` |
| `query_digest` | `protocol_fixed` | `81c610fe9830b111fe218d68247f5ed1af33ceb2190c0fca2f3719be415bbc7d` | `81c610fe9830b111fe218d68247f5ed1af33ceb2190c0fca2f3719be415bbc7d` | `equal` | `controlled` |
| `query_family_id` | `arm_observed` | `synthetic-benefit-eligibility` | `synthetic-benefit-eligibility` | `equal` | `controlled` |
| `request_digest` | `protocol_fixed` | `8da4857cfd203a6a91c33c8a4e5d8745534500ebc388669ef4701f5a5c8f550e` | `8da4857cfd203a6a91c33c8a4e5d8745534500ebc388669ef4701f5a5c8f550e` | `equal` | `controlled` |
| `retrieval_algorithm` | `arm_observed` | `deterministic-term-overlap@1.0.0` | `deterministic-term-overlap@1.0.0` | `equal` | `controlled` |
| `retrieval_top_k` | `arm_observed` | `1` | `1` | `equal` | `controlled` |
| `subject_configuration_digest` | `protocol_fixed` | `3d006eed7d9755fde1d5ef469d910a1df4b4ca0fcaebeddae035802fb3339835` | `3d006eed7d9755fde1d5ef469d910a1df4b4ca0fcaebeddae035802fb3339835` | `equal` | `controlled` |
| `suite_digest` | `protocol_fixed` | `a96a7e32c50125b30ff768757cce01a121d11a65adb4b0fd5951ccfe6e6038fc` | `a96a7e32c50125b30ff768757cce01a121d11a65adb4b0fd5951ccfe6e6038fc` | `equal` | `controlled` |
| `tool_configuration_digest` | `protocol_fixed` | `e58a15c3e6d3b530e0149b393001ba9536a068d70aeade5dacdb868ca5c38d07` | `e58a15c3e6d3b530e0149b393001ba9536a068d70aeade5dacdb868ca5c38d07` | `equal` | `controlled` |
| `tool_schema_digest` | `protocol_fixed` | `ab72f2449da6de27489c10fe35c6bc5e6431d3cede8f13eff0e769dfe52dc498` | `ab72f2449da6de27489c10fe35c6bc5e6431d3cede8f13eff0e769dfe52dc498` | `equal` | `controlled` |

## Prerequisites

- `arm-evaluations-pass`: `satisfied`
- `authority-contract-valid`: `satisfied`
- `comparable-decision-output`: `satisfied`
- `controlled-differences-only`: `satisfied`
- `deterministic-subject`: `satisfied`
- `evidence-links-present-both-arms`: `satisfied`
- `fixture-identity-bound`: `satisfied`
- `governing-evidence-supported-both-arms`: `satisfied`
- `retrieval-succeeded-both-arms`: `satisfied`

## Assumptions

- The knowledge-authority contract correctly declares which contextual evidence governs the synthetic task.
- The committed fixture subject and lexical retriever are deterministic contract-test components, not measurements of a hosted model.

## Limitations

- This deterministic synthetic detector contract test does not estimate real-model prevalence.
- Controlled evidence sensitivity is an observed response relation under declared conditions, not a causal guarantee.
- Synthetic declarative fixture harness/oracle only; this result does not show that a model used contextual evidence instead of parametric memory.
- Agent implementation, prompt, model, and tool-schema digests are fixture-declared identifiers; this protocol does not verify them against implementation, prompt, model, or tool-schema bytes.
- Exact raw corpus and fixture UTF-8 is embedded verbatim in reports and packets; bundled synthetic status is digest-verified, while custom synthetic status is operator-attested and not semantically verified.
- Synthetic fixture outputs do not estimate evidence-insensitivity prevalence in real models.
