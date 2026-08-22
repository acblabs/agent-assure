# Process-Equivalence Reproduction Index v0.1: controlled evidence sensitivity

This committed, synthetic example is a declarative fixture harness and detector
contract test. It does not demonstrate that a model used contextual evidence
instead of parametric memory, measure failure prevalence in real models, or
establish a causal guarantee.

Policy A authoritatively requires approval. Policy B authoritatively requires
denial. All three deterministic subjects rerun from the beginning, retrieve the
governing policy, and emit an exact claim-to-evidence link:

- responsive_suite.yaml follows the governing corpus and passes the expected
  decision-response endpoint.
- evidence_reversed_suite.yaml is an explicit wrong-flip negative control: it
  keeps governing retrieval and claim-evidence links but reverses the
  authority-bound decision. The observed decision flip is not evidence
  inertia, yet the endpoint blocks the evidence-insensitive output.
- evidence_inertial_suite.yaml intentionally keeps approving and is blocked
  even though ordinary retrieval, citation, and evaluation checks pass.

Run any experiment with agent-assure rag sensitivity; the agent-assure demo
evidence-sensitivity command runs and validates the responsive and inertial
controls.

The Process-Equivalence Reproduction Index binds this complete directory as a
source closure: every recursive regular source file is represented by its
sorted relative path and SHA-256. Runtime cache artifacts such as `__pycache__`
and `.pyc` files are excluded by the declared inventory policy.
