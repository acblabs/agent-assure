# Evidence-Carrying Agent Releases

Contract status: development RFC for the `v1` evidence and mutation contracts.

`agent-assure` is an Agent Release Assurance Compiler. It applies individually
selected, versioned challenges to privacy-filtered agent-process artifacts and
records whether the declared control emitted its expected finding. The result
is scoped evidence about one subject, operator, and control contract. It is not
a general safety or compliance conclusion.

## Contract Set

The initial contract set has four durable JSON objects:

- `AssuranceEvidenceDescriptor/v1` carries method identity, scope,
  prerequisites, assumptions, limitations, dependencies, and validity.
- `AssuranceMutationOperator/v1` describes one deterministic transformation
  and the schema-owned paths it may change.
- `ExpectedDetectionContract/v1` defines which control finding counts as the
  expected detection and which substitute findings do not count.
- `AssuranceMutationResult/v1` binds the source, transformed subject, operator,
  observed findings, and semantic state. The evidence descriptor depends on
  the result digest so the two-artifact relationship is explicit and acyclic.

Each root uses persisted `schema_version: 0.6.0`, a `contract_id` ending in
`/v1`, and `contract_version: 1.0.0`. The contract version identifies method
semantics; the schema version identifies the persisted JSON shape. A contract
version must not be used to relabel an artifact from another schema release.

## Evidence Descriptor

The following is the complete representative shape emitted for a caught
`drop-material-evidence-link` execution. Angle-bracketed values are derived for
each execution; all other values are producer-owned contract values.

<!-- BEGIN: emitted-caught-evidence-descriptor -->
```yaml
artifact_kind: assurance-evidence-descriptor
schema_name: assurance-evidence-descriptor
schema_version: 0.6.0
contract_id: AssuranceEvidenceDescriptor/v1
contract_version: 1.0.0
evidence_id: "ev-control-efficacy-<result-digest-prefix-24-hex>"
evidence_digest: "<evidence-digest-64-lowercase-hex>"
evidence_kind: control_efficacy

subject:
  subject_type: run_set
  digest: "<source-runset-digest-64-lowercase-hex>"

scope:
  suite_digest: "<compiled-suite-digest-64-lowercase-hex>"
  protocol_digest: null
  population_id: deterministic-fixture-v1
  gate_profile_id: default
  gate_profile_digest: "<gate-profile-digest-64-lowercase-hex>"
  waiver_set_digest: "<waiver-set-digest-64-lowercase-hex>"
  evaluation_date: "<evaluation-date-yyyy-mm-dd>"

method:
  method_id: assurance-mutation/core/v1
  implementation_digest: "<evaluator-implementation-digest-64-lowercase-hex>"
  implementation_version: 0.6.0
  evaluation_basis: deterministic

result:
  state: supported
  verdict_bearing: true
  reason_codes:
    - MATERIAL_CLAIM_MISSING_EVIDENCE
  metrics:
    observed_finding_count: 1
    matched_finding_count: 1

prerequisites:
  state: satisfied
  checks:
    - check_id: subject-valid
      state: satisfied
      reason_codes: []
    - check_id: operator-valid
      state: satisfied
      reason_codes: []
    - check_id: operator-applicable
      state: satisfied
      reason_codes: []
    - check_id: mutation-execution-completed
      state: satisfied
      reason_codes: []

assumptions:
  - When validated, the compiled suite and RunSet bindings identify the intended deterministic subject.
  - The bound evaluator implementation provides the declared target controls.
limitations:
  - Detection is scoped to this deterministic operator, subject, suite, and gate profile.
  - The finite operator does not represent every evidence-link failure.
  - The operator challenges one deterministically selected material claim.

validity:
  generated_at: "<generated-at-rfc3339-timestamp>"
  expires_at: null
  invalidated_by:
    - canonicalization_component_digest_change
    - evaluator_or_gate_component_digest_change
    - evaluation_date_change
    - expected_detection_contract_digest_change
    - gate_profile_digest_change
    - mutation_dispatch_component_digest_change
    - mutation_schema_or_validation_component_digest_change
    - operator_implementation_manifest_digest_change
    - privacy_component_digest_change
    - suite_digest_change
    - target_control_component_digest_change
    - waiver_set_digest_change

dependencies:
  - evidence_id: "mutation-result-<result-digest-prefix-24-hex>"
    digest: "<mutation-result-digest-64-lowercase-hex>"
producer:
  name: agent-assure
  version: 0.6.0
```
<!-- END: emitted-caught-evidence-descriptor -->

The population profile is identified by `deterministic-fixture-v1`. The scope
also binds the complete canonical gate-profile digest, the order-independent
waiver-set digest (including an explicit empty set), and the waiver evaluation
date. The source RunSet's privacy-profile identity and digest remain bound
through the canonical subject digest rather than being duplicated here.

Its canonical digest uses the repository's RFC 8785 JSON path and excludes
`evidence_digest` from its own digest projection. Missing prerequisites are
never treated as satisfied. Evidence with unmet prerequisites is not
verdict-bearing, and only such non-verdict evidence may omit the subject digest.
`generated_at` remains inside the descriptor projection, so `evidence_digest`
identifies one emission and may differ when the same deterministic mutation is
described again. Replay must anchor on the mutation `result_digest` and, when a
mutation was produced, the canonical mutated RunSet bytes—not on
`evidence_digest`.
The `assurance-mutation/core/v1` method requires exactly the four canonical
checks shown above, in this order: `subject-valid`, `operator-valid`,
`operator-applicable`, and `mutation-execution-completed`. Limitations remain
attached in every supported projection.

## Mutation Operator

Each operator candidate in this development RFC declares:

- deterministic operator ID and semantic version;
- compatible input artifact kinds and schema versions;
- machine-checkable preconditions;
- permitted changed paths;
- privacy classification;
- implementation digest;
- a canonically ordered, fail-closed manifest of first-party Python and loaded
  frozen-schema component paths with normalized SHA-256 digests covered by that
  implementation digest;
- origin and authorship provenance;
- independence class; and
- one expected-detection contract and its digest.

The engine validates the source, works from an immutable copy, checks that no
undeclared path changed, and validates the transformed object. The same source
digest, complete operator identity, and integer seed produce identical
transformed bytes. `result_digest` self-hashes every serialized result field
except `result_digest` itself, so it is identical only when the complete result
projection is unchanged. That projection includes the source and transformed
digests; operator, implementation, expected-detection, and provenance
identities; evaluator method, version, implementation, evaluation basis,
protocol, and population identities; gate-profile and waiver-set identities;
the evaluation date and seed; and the resulting changed paths, findings,
matches, state, diagnostics, and limitations.
CLI replay that requires an identical result digest must therefore pass the
same `--today` value. If `--today` is omitted, the command uses the current date,
which is intentionally part of the result digest.

Changed paths use schema-owned JSON Pointer identities. Reports contain paths,
digests, reason codes, and bounded summaries rather than copied field content.
Permitted operator paths use schema-visible single-segment wildcard templates;
result paths are exact JSON Pointers and cannot contain a wildcard token.

Introduction evidence is deliberately separate from current implementation
identity. `implementation_components` is the complete current code/data manifest
used to derive `implementation_digest`; it changes when the implementation
evolves. `introduction_components` is an authored, frozen per-operator snapshot
of the catalog and transformation bindings that established the operator.
`digest_at_operator_creation` is a separate authored snapshot of the target
control. Neither historical snapshot is recomputed from the live implementation
manifest. The per-operator snapshot is also stored in
`agent_assure/mutation/introduction_snapshots.json`; release validation reads
that document from the immutable introduction commit and requires it to match
the carried `introduction_components`, so a later release cannot silently
rewrite the claimed historical binding.

Source line endings are normalized to LF before hashing. The catalog component
additionally normalizes only the administrative `introduced_at_commit` literal,
so the required follow-up stamping commit does not circularly change the method
identity it authenticates. All other source bytes remain identity-bearing.
Once `introduced_at_commit` identifies an immutable Git commit, release
preparation replays the frozen introduction-component digests and verifies the
authored target-control snapshot against the corresponding blobs in that
commit. It does not compare current component bytes with historical bytes. It
also requires `introduced_in_release` to be no newer than the concrete expected
package/tag version under release-candidate-aware SemVer precedence, proves that
the introduction commit is an ancestor of the release commit, and proves each
target control's `first_seen_commit` is an ancestor of the operator introduction.
This establishes that the operator bindings and target existed in the claimed
history while allowing their current implementation identity to evolve in later
releases. An unstamped
`git:uncommitted` operator remains usable for local development but fails
release provenance validation; ancestry cannot be asserted until the
implementation has been committed and the follow-up provenance stamp exists.

The built-in catalog is constructed lazily from package resources and cached
for the process. Missing or unreadable identity components fail the requested
mutation with a bounded `catalog_integrity_error`; importing unrelated CLI
commands does not construct the catalog.
If that failure occurs before the evaluator manifest can be materialized, the
non-verdict mutation result uses the all-zero unavailable-identity sentinel.
That sentinel is valid only for `execution_error` with
`catalog_integrity_error`; it is not an evaluator implementation digest and can
never support `caught` or `survived`.

## Expected Detection

An expected-detection contract is explicit:

```yaml
artifact_kind: expected-detection-contract
schema_name: expected-detection-contract
schema_version: 0.6.0
contract_id: ExpectedDetectionContract/v1
contract_version: 1.0.0
contract_digest: <64 lowercase hexadecimal characters>
operator_id: drop-material-evidence-link
target_control_ids:
  - material_claims_have_evidence
required_findings:
  any_of:
    - control_id: material_claims_have_evidence
      reason_code: MATERIAL_CLAIM_MISSING_EVIDENCE
prohibited_substitutes:
  - control_id: runtime_success_required
    reason_code: RUNTIME_FAILED
expected_gate_effect: block
secondary_findings_allowed: true
```

`caught` requires a required finding from a target control and the declared
gate effect. An unrelated parser, schema, runtime, or policy failure does not
count. If the transformation accidentally creates an invalid subject, the
result is `invalid_operator`, not `caught`. Every referenced control and reason
code must exist in the running implementation.

Gate effects are evaluated against the report's authoritative projections:
`block` requires failed-control membership, `review` requires warning-only
membership, and `informational` or `ignore` requires the finding to be in
neither gating projection. The latter two are distinct declared intentions
with the same non-gating projection in this contract version.

## Built-In Operators

The initial built-ins target three existing deterministic control families:

| Operator | Permitted change | Expected control | Expected reason code |
| --- | --- | --- | --- |
| `drop-material-evidence-link` | Remove all evidence links for one applicable material claim | `material_claims_have_evidence` | `MATERIAL_CLAIM_MISSING_EVIDENCE` |
| `bypass-required-human-review` | Remove the applicable required/performed review state | `human_review_required` | `REQUIRED_HUMAN_REVIEW_ABSENT` |
| `inject-forbidden-tool` | Add one tool outside the applicable allowlist or in the forbidden set | `tool_allowlist` | `FORBIDDEN_TOOL` |

Applicability describes whether the source has a valid mutation target. It is
separate from whether the configured control detects the change. A deliberately
weakened control can therefore yield `survived` for an otherwise applicable
operator.

## Result Contract

A mutation result records:

- source artifact kind and canonical digest when the subject validates;
- transformed artifact digest when a valid mutation is produced;
- operator ID, version, operator digest, and implementation digest;
- evaluator method ID, semantic implementation version, and verified non-zero
  implementation digest, except for the narrowly scoped catalog-bootstrap
  unavailable-identity sentinel described above;
- integer seed;
- exact changed paths;
- expected-detection contract and selected finding-target digests;
- observed finding IDs, control IDs, states, reason codes, and target digests;
- finding IDs that matched the normative detector;
- provenance and independence class;
- semantic result state;
- bounded diagnostic code and limitations; and
- its canonical result digest.

Finding targets themselves are not copied into the result. Instead, the
selected expected target and every observed finding target use the same
domain-separated canonical digest. Every matched finding must carry the
selected target digest, so an offline reviewer can audit target equality
without exposing the target string in the result.

The built-in evaluator digest is derived from the catalog's fail-closed
first-party component manifest. It covers every packaged `agent_assure` Python
source file (including package initializers and their import side effects) and
every frozen legacy RunSet schema loaded during validation, in addition to the
runtime dependency versions. This deliberately over-binds the implementation
rather than allowing an unreviewed transitive import to affect findings under
an unchanged evaluator identity. Evaluation reports also carry the canonical
digest of the RunSet content they evaluated; mutation execution rejects a
source or candidate report whose ID or content digest does not match. A
programmatic custom or deliberately weakened evaluator is accepted only through
an explicit `MutationEvaluatorBinding` carrying its callable, method ID,
semantic implementation version, and non-zero implementation digest. A bare
callable has no admissible evaluator provenance.

The other contract roots use the same split versioning:
`AssuranceMutationOperator/v1` carries `operator_digest`, and
`AssuranceMutationResult/v1` carries `result_digest`. Each self-digest is
excluded only from that object's own RFC 8785 digest projection.

The descriptor's general evidence state and the mutation result state are
different vocabularies. A descriptor may bind a mutation result as evidence,
but it does not relabel or replace `caught`, `survived`, or the other mutation
states. `supported` in a descriptor means only that the scoped evidence claim
was supported under its declared method and prerequisites.

Semantic states are:

- `caught`: the normative expected-detection contract was satisfied;
- `survived`: the transformation was applicable and valid, but the normative
  detector was not satisfied;
- `inapplicable`: the source has no valid target for this operator;
- `invalid_operator`: the operator violated its own contract or produced an
  invalid transformed subject;
- `invalid_subject`: the source cannot be validated as a compatible subject;
- `execution_error`: bounded execution failed for a reason not represented by
  the other states.

`inapplicable` and `execution_error` never count as detection.

## CLI

Single-operator execution uses:

```bash
agent-assure controls mutate \
  --suite assurance/suite.yaml \
  --runset runs/baseline.json \
  --operator drop-material-evidence-link \
  --seed 0 \
  --today 2026-07-20 \
  --out reports/mutation
```

The command writes the transformed subject when one is produced and a
machine-readable mutation result. It accepts either authored suite YAML or a
compiled-suite JSON artifact. The output files are
`assurance-mutation-result.json`, `assurance-evidence-descriptor.json`,
`mutation-generation-manifest.json`, and, for `caught` or `survived`,
`mutated-runset.json`. `--waiver`, `--fail-on-warn`,
`--fail-on-not-evaluated`, and `--today` use the same gate configuration
semantics as deterministic evaluation. Its documented RFC exit map is:

| Exit | Meaning |
| ---: | --- |
| `0` | `caught` |
| `1` | `survived` |
| `2` | invalid (`invalid_operator` or `invalid_subject`) |
| `3` | `inapplicable` |
| `4` | `execution_error` |

The result artifact preserves the more specific invalid state even though both
invalid states share exit `2`.

Output is committed as one staged generation under a per-directory writer
lock. The generation manifest is atomically published last as the commit
marker; readers reject missing or digest-incoherent generations. Reusing an
output directory removes a stale transformed RunSet when the new state has no
transformation, and a failed replacement rolls back the prior fixed-file
generation. The command rejects lexical, resolved, symlink, junction, or
hardlink aliasing between the suite, source RunSet, or waiver inputs and any
fixed output path.

## Provenance and Independence

Operator provenance records the operator version and implementation digest,
origin references, its relationship to the target control and control author,
and available introduction identities. Independence classes are:

1. `external_preexisting`
2. `third_party_contributed`
3. `first_party_precontrol`
4. `first_party_postcontrol`
5. `unknown`

`first_party_postcontrol` is weaker challenge evidence because the operator was
designed after the target control was known, often by the same project. It can
still expose a real defect, but it is more susceptible to shared assumptions
and implementation-aware test design than an external, pre-existing challenge.
Reports preserve this distinction instead of presenting all operators as
equally independent.

A development-tree operator may carry `git:uncommitted` as its introduction
identity when no truthful immutable commit exists yet. Release preparation
fails closed while that placeholder remains. Publishing therefore requires a
follow-up provenance update after the implementation has an immutable commit;
the placeholder is never treated as release-ready evidence. At introduction,
the catalog/operator binding digests are frozen in the authored
`introduction_components` snapshot. Later releases update the live
`implementation_components` identity without rewriting that snapshot.

## Privacy and Security

Mutation is limited to validated schema-owned fields. Synthetic fixtures may
contain clearly labeled synthetic content; ordinary mutation reports do not
copy prompts, completions, raw messages, tool arguments, tool results, token
chunks, credentials, or unredacted summaries.

Loaders reject oversized, over-depth, duplicate-key, non-finite, malformed, or
incompatible inputs. Operator execution does not deserialize executable
objects, invoke caller-supplied shell text, load executable plugins, or require
network access.

Source RunSets must already satisfy the bound privacy-detector profile. A
detector match in any persisted string makes the source `invalid_subject`;
operator output that introduces one is `invalid_operator`. The engine does not
silently rewrite either artifact because doing so would invalidate the recorded
source digest or declared changed paths. Sensitive-looking unknown operator
identifiers are replaced with the fixed `unknown-operator` identity in output.

## Limitations

- Each result covers one declared operator and one exact subject.
- Authored deterministic cases do not estimate real-world failure prevalence.
- A caught mutation establishes only that the expected control responded to
  that transformation under the bound configuration.
- A survived mutation identifies a control gap for that case; it does not
  estimate the probability of a production failure.
- Operator implementation and expected-detection contract changes invalidate
  earlier identity unless compatibility is explicitly established.
- LLM-derived judgments are advisory and cannot satisfy expected detection or
  determine a gate.
