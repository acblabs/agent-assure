# Process-Equivalence Benchmark v0.2

This directory publishes non-sensitive, digest-bound inputs and executable RAG
authority fixtures for the preregistered real-model study workflow. It contains
no model output, observation, credential, provider result, or empirical claim.

The 168 canonical cases form four homogeneous study strata with 42 separately
committed case-ID clusters each:

- approve -> deny decision flips;
- deny -> approve decision flips;
- approve -> approve invariant controls; and
- deny -> deny invariant controls.

Every eligibility score from 50 through 91 occurs once in every stratum, so the
visible score does not identify the expected relation or direction. The fixture
is a controlled conformance frame, not a population sample.

A repeated protocol binds one executable knowledge contract, relation, and
decision orientation. Accordingly, the benchmark publishes four contracts at
knowledge-contracts/{authority_contract_id}.json. The exact raw UTF-8 SHA-256
of that file is the source_digest shared by the 42 cases in its stratum. Sharing
that outer digest does not duplicate case evidence: every explicit case binding
inside the contract commits to its own baseline and counterfactual corpus
digests, governing-document content digests, source identity, reference
identity, and claim identity.

Each input_digest commits to the exact bytes of inputs/{case_id}.json.
authority-contract.json resolves every case to both executable corpus manifests.
Each manifest is self-digested and its document descriptor hashes the adjacent
governing-policy.json byte for byte. Across the benchmark there are 168 unique
input commitments, 168 unique logical governing-source identities, 336 unique
corpus digests, and 336 unique governing-content commitments.

The four-condition authoring template uses all 42 frozen clusters per stratum.
Bonferroni correction covers the two decision-flip targets, not the two exact-
gate invariant controls, so familywise alpha 0.05 becomes 0.025 per inferential
target. Each directional claim is separately FWER-controlled at 0.05; the
combined support-or-contradiction rule is not a single joint two-sided-alpha
guarantee. At materiality threshold 0.10, zero inertia clusters have one-sided
upper bound 0.084083854941, nine have lower bound 0.102959649897, and counts one
through eight are inconclusive. Thus contradiction requires zero observations
in both targets while support requires at least nine in either target.

This is a finite conformance frame built from one task, not a population sample
or a collection of independent task families. Within each stratum the visible
input differs only by one integer eligibility score. Unique case IDs, source
identities, fixture commitments, and input digests make each case replayable and
exclude byte-identical prompts; they do not measure semantic similarity or
prove independent, exchangeable model behavior. Confirmatory use is conditional
on a preregistered substantive justification of that assumption, and reported
results remain scoped to this exact frame. The shipped authoring template
therefore carries an explicit unresolved independence basis. It cannot be used
for real-provider preregistration or statistical-method approval until an
author replaces it with a positive, design-specific argument and a qualified
independent statistical reviewer accepts that exact digest-bound design.

The confirmatory inertia endpoint counts every coherent same-decision cluster,
whether its baseline arm matched the preregistered expected recommendation and
outcome or not. Published reports additionally provide a descriptive,
non-inferential split into uniformly baseline-matching, uniformly
baseline-nonmatching, and mixed-baseline-correctness inertia clusters. Here
“baseline-correct” means only agreement with that preregistered expected tuple;
it is not an assertion of external, clinical, or policy truth.
