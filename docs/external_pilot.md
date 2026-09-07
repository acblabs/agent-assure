# External CI Pilot Evidence

Status: development contract. This repository contains no qualifying external
CI pilot record. The template in this documentation is deliberately
`not_attempted` and does not establish adoption, independent use, or a release
gate.

`ExternalPilotEvidence/v1` records whether another team could attempt one
signature workflow in a real CI environment, what friction they encountered,
and what remediation followed. It is learning evidence. It is not a customer
testimonial, clean-room attestation, safety assessment, or substitute for a
later exact-candidate validation.

## What Qualifies as an External Attempt

`qualifies_as_external_attempt` is derived rather than freely asserted. It is
true only when all of these facts are present and internally consistent:

- `classification` is `external`;
- `attempt_status` is `attempted` or `completed`;
- `workflow_id` is `controls-mutate` or `rag-sensitivity`, and at least one
  recorded command directly invokes that declared Agent Assure workflow with
  its complete execution-bearing option set;
- execution occurred in `continuous_integration`;
- the repository or environment is recorded as
  `independently_controlled_non_maintainer` with a digest-bound control-evidence
  artifact;
- at least one configuration or data input is `non_bundled`;
- at least one exact command, its timing, exit code, and execution-evidence
  digest are recorded; and
- friction was assessed.

An `attempted` record may document a failed or blocked onboarding path; that
failure is valuable pilot evidence when it is recorded accurately. A
`completed` record additionally requires a schema-valid assurance-output
artifact. The assurance verdict itself may legitimately block—the word
`completed` means the integration operated as designed, not that every tested
control passed.

Internal dogfood, a maintainer-controlled repository, a synthetic clone,
bundled-only fixtures, local execution, or unverified environment control does
not qualify. Record such work using `internal_dogfood` or `synthetic` rather
than upgrading its provenance label.

The matching command may use an `agent-assure` console launcher (including an
absolute/relative path or `.exe` form) or `python`, `python3`, or `py -m
agent_assure.cli.main`. The package root has no module entry point, so `-m
agent_assure` does not qualify. Setup commands may coexist, but wrappers and
unrelated commands do not prove that the declared signature workflow was
attempted. Help, version, bare-prefix, missing-required-option, repeated
single-option, positional, unsupported-option, and stochastic RAG subcommand
forms are non-executing or ambiguous and do not qualify.

## Evidence Record

Start from the
[external-pilot authoring template](https://github.com/acblabs/agent-assure/blob/main/docs/templates/external_pilot_evidence.yaml).
It defaults to a private, not-attempted planning record and omits the derived
`pilot_evidence_digest`. Finalize it with the bounded, no-clobber authoring
command; the CLI calls `ExternalPilotEvidence.build(...)`, computes the digest,
emits canonical JSON, and verifies an exact model round trip:

```bash
agent-assure release pilot finalize \
  --template docs/templates/external_pilot_evidence.yaml \
  --out evidence/empirical/external-pilot/external-pilot-evidence.json

agent-assure validate evidence/empirical/external-pilot/external-pilot-evidence.json \
  --kind external-pilot-evidence
```

The template may be JSON, YAML, or YML. A supplied
`pilot_evidence_digest` is ignored and recomputed. Existing output is accepted
only when its bytes are exactly the canonical result; different content is
never overwritten.

The output must live in a dedicated directory below the command's working
directory when it is part of that working tree. The persistent no-clobber lock
lives beside that directory so it cannot enter the later closed bundle
inventory. A direct-current-directory output, including the CLI's bare default,
fails with an explicit error rather than creating a lock in the parent
directory.

The final record binds:

- a pseudonymous participant and workflow ID;
- implementation version, source revision, and tested distribution digest;
- platform and canonically ordered component versions;
- the independently controlled environment manifest and its control evidence;
- non-bundled configuration/data origins and exact aggregate digests, derived
  from a schema-valid `PilotInputManifest/v1` that records each input-bearing
  option, its privacy-safe path, origin, kind, and content SHA-256;
- exact argv arrays, working-directory identity, environment-variable names,
  timestamps, exit codes, execution evidence, tested wheel and source-revision
  bindings, and the exact input-manifest entries consumed by each command;
- privacy-filtered artifact digests and optional schema contracts;
- a unique portable direct-child path for every referenced artifact and, for
  each assurance output, the exact command that produced it;
- friction findings and digest-bound remediation records;
- consent status and publication scope; and
- explicit privacy assertions, limitations, and non-gating semantics.

To turn the safe template into an observed attempt, first replace the subject,
distribution, environment, component, and input placeholders with reviewed
facts. After the external execution:

1. set environment control to
   `independently_controlled_non_maintainer` and add its dedicated
   `environment_control_evidence` artifact;
2. replace `input-manifest.json` with a `PilotInputManifest/v1` containing one
   canonical entry for every input-bearing workflow option, bind its derived
   configuration/data digests into `inputs`, and declare the manifest artifact
   as schema-valid under that exact contract;
3. add commands in contiguous execution order, with exact argv, privacy-safe
   environment-variable names, timestamps, exit codes, matching
   `execution_evidence` artifacts, the tested-distribution artifact/digest and
   source revision, and the sorted input entry IDs consumed by each command; at
   least one command must directly invoke
   `agent-assure controls mutate ...` for `controls-mutate` or
   the deterministic `agent-assure rag sensitivity [OPTIONS]` callback for
   `rag-sensitivity`; its `plan`, `finalize`, `analyze`, and stochastic
   live `run` subcommands do not qualify;
4. set `attempt_status: attempted` and
   `qualifies_as_external_attempt: true`;
5. add a `friction_assessment` artifact and either a no-friction state or
   linked findings and remediation records;
6. use `attempt_status: completed` only when at least one
   `assurance_output` artifact is marked schema-valid under the exact contract
   produced by the recorded command: `AssuranceMutationCampaign/v1` for
   catalog mutation, `AssuranceMutationResult/v1` for one-operator mutation,
   or `RAGSensitivityReport/v1` for deterministic RAG sensitivity. Set its
   `producing_command_id` to that command; its exit code must be an
   evidence-bearing completion code (`0` or `1`), not a usage, collision,
   or runtime-failure code; and
7. set `recorded_at` no earlier than the last command completion, sort
   artifacts/findings/remediations by their canonical IDs, then derive
   `pilot_evidence_digest` with the model builder.

The builder rejects a manually asserted external qualification when those
facts do not support it.

Do not put credential values, direct participant identifiers, raw inputs, raw
outputs, or confidential repository content into the evidence record. Command
arguments must also be reviewed because process arguments can expose secrets.
The schema rejects credential-bearing options, curl user/password forms,
authorization and cookie headers, URI userinfo or secret query parameters,
secret-valued assignments, and recognizable token literals. Record
environment-variable names or non-secret file references only; retain values
in the external team's approved secret store.

## Friction and Remediation

Every attempted pilot must produce either `friction_observed` or
`no_friction_observed` with a digest-bound assessment artifact. When friction
is observed, each finding references both its evidence and at least one
remediation record. Remediation may be `applied`, `planned`, `deferred`, or
`no_change_required`, and can target onboarding, initialization, diagnostics,
documentation, integration, the in-place roadmap, or another recorded area.

For the empirical checkpoint, `no_friction_observed` is complete learning.
When friction is observed, learning is complete only after at least one
finding-linked remediation is `applied` and targets `onboarding`,
`initialization`, `diagnostics`, or `roadmap`. Honest planned, deferred,
no-change-required, documentation-only, integration-only, or `other`
remediations remain recordable, but do not satisfy that readiness projection.

The purpose is an auditable learning loop:

```text
independent CI attempt -> privacy-safe friction evidence -> bounded remediation
```

An unassessed attempt is rejected. A friction finding without a remediation
reference is rejected. A remediation not connected to a finding is rejected.
These rules prevent a bare execution log from being presented as adoption
learning.

## Consent and Publication

The default publication scope is `private_record`. If consent has not been
requested, the record cannot include a consent artifact or published artifact
IDs. `aggregate_summary` and `privacy_filtered_record` require granted consent
anchored to an exact consent artifact and digest. A privacy-filtered publication
must enumerate the exact published artifacts.

The repository-backed public release gate is narrower than the general record
schema. It requires `consent_status: granted`,
`publication_scope: privacy_filtered_record`, and
`published_artifact_ids` equal to the complete canonically ordered
`artifacts[].artifact_id` inventory. The checked-out bundle contains every
declared artifact, so `private_record`, `aggregate_summary`, withheld
consent, and partial publication authorization all block readiness with
`external-pilot-publication-not-authorized`. They remain valid non-release
records and should not be committed as public empirical evidence.

Schema validity proves only internal structure and digest relationships. It
does not verify repository ownership, participant independence, consent
authority, artifact truth, or that the described command actually ran. Review
the external control evidence and consent out of band before making any public
statement.

## Verified Bundle and Independence Review

A bare `ExternalPilotEvidence/v1` JSON file cannot satisfy the publish gate.
Before review, the release operator must assemble a closed, flat directory
containing only the finalized evidence and every declared artifact. Keep the
human review template outside this directory. The review command adds the sole
missing receipt, producing:

```text
evidence/empirical/external-pilot/
  external-pilot-evidence.json
  external-pilot-independence-review.json
  agent_assure-0.6.6-py3-none-any.whl
  <one direct-child file for every artifacts[].path>
```

After completing the out-of-band checks, copy the human-only template to an
operator-controlled location, fill its attestations, and run:

```bash
agent-assure release pilot review \
  --bundle-root evidence/empirical/external-pilot \
  --evidence external-pilot-evidence.json \
  --template /tmp/external-pilot-independence-review.yaml \
  --out external-pilot-independence-review.json
```

The template accepts only the receipt ID, reviewer pseudonym, manual trust-root
and independence attestations, independence rationale, completed reviews of
the environment-control evidence, artifact inventory, tested-distribution
provenance, command/input bindings, and privacy boundary, the approved outcome,
and review time. It rejects pilot IDs, release lines, digests, artifact
references, review-method claims, and other derived fields. The command derives
those fields from the validated bundle, calls the
self-digesting receipt builder, publishes canonical JSON without overwriting
different bytes, and immediately verifies the resulting complete bundle.
Persistent advisory locks live beside the resolved bundle directory rather
than inside it, preserving the closed inventory. The bundle directory cannot be
the current working directory or its ancestor, and the lock cannot be placed at
a filesystem root; run the command from the bundle's parent and pass the bundle
as a child path. An exact rerun, including one using the same template bytes
from another directory, succeeds idempotently. If post-publication verification
fails, readiness remains closed; restore the exact reviewed inputs and rerun,
or assemble a new clean bundle rather than overwriting the receipt.

Every artifact descriptor has a unique portable direct-child `path`. Nested,
absolute, traversal, backslash, reserved-device, and case-colliding paths are
rejected. The directory inventory must be exactly the evidence descriptor,
review receipt, and referenced artifacts: missing and undeclared entries both
fail. The checker leases one no-follow root, retains every child handle through
validation, rejects links, reparse points, special files, and multiply-linked
files, and revalidates the handles and exact inventory before returning. Reads
are capped at 16 MiB per artifact, 64 MiB for the complete bundle, and 258
files.

The tested distribution must be an `agent-assure` wheel. The checker validates
its archive member paths and bounds, filename identity, Core Metadata
`Name`/`Version`, `.dist-info` identity, mandatory `WHEEL` metadata and
filename-bound compatibility tags, exact `RECORD` inventory, sizes, and
SHA-256 entries against the pilot subject. Arbitrary bytes cannot stand in for
a distribution. Non-distribution artifacts must be bounded UTF-8 metadata;
their nested JSON keys and values (or every line of non-JSON text) pass the
privacy detectors. A declared schema contract is validated from the actual
bytes against a closed allowlist. Unsupported contract names fail rather than
being trusted.

After inspecting the exact evidence, artifact inventory, environment-control
evidence, and privacy boundary, a release operator starts from the
[independence-review checklist](templates/external_pilot_independence_review.yaml)
and uses the command above to persist a separately self-digested
`ExternalPilotIndependenceReviewReceipt/v1`. The receipt binds:

- the pilot ID, participant pseudonym, logical evidence digest, and raw evidence
  file SHA-256;
- the canonical full artifact descriptor manifest, including roles, paths,
  scopes, schemas, producer links, and byte digests;
- the exact environment-control artifact ID and SHA-256;
- the expected stable release line; and
- a distinct reviewer pseudonym, independence rationale, completed review
  checklist, outcome, and review time no earlier than the evidence record.

This is deliberately modeled as `human_operator_attestation` with
`reviewer_identity_authentication:
out_of_band_not_machine_verified`. The checker verifies receipt structure,
self-digest, timing, and exact bindings; it does **not** authenticate the
reviewer's identity or cryptographically establish independence. Repository
review and release-environment approval are the manual trust root. If a threat
model requires independence from a hostile evidence producer, require a
separately verified signature/OIDC identity under organizational policy; this
receipt alone is insufficient.

The publish-gate invocation is:

```bash
python scripts/check_empirical_readiness.py \
  --study-bundle-root evidence/empirical/real-model-study \
  --external-pilot-bundle-root evidence/empirical/external-pilot \
  --external-pilot-evidence external-pilot-evidence.json \
  --external-pilot-review-receipt external-pilot-independence-review.json \
  --expected-release 0.6.6rc1
```

The Python readiness projection follows the same boundary:
`assess_empirical_readiness` accepts only the factory-only
`VerifiedExternalPilotBundle` returned by
`load_verified_external_pilot_bundle`. A parsed or self-authored
`ExternalPilotEvidence` object cannot be passed directly and cannot satisfy
the checkpoint through an alternate in-memory call path.

The release-log JSON preserves the assessor's exact `blocking_reasons` when
validated evidence is ineligible. A genuinely absent study or pilot bundle
root is passed to the assessor as evidence that has not yet been verified, so
the log reports actionable reasons such as
`real-model-study-bundle-not-verified` and
`external-ci-pilot-not-attempted`. If an existing bundle cannot be loaded or
validated before an assessment can be produced, the gate remains closed with
`empirical-evidence-invalid-or-unavailable` and adds a value-free
`failure_category` containing only the exception class name (for example,
`FileNotFoundError`, `ValueError`, or `TypeError`). Exception messages and
validation values are never copied into the release log.

## Release-Gate Boundary

Every `ExternalPilotEvidence/v1` record fixes:

```text
evidence_phase: pre_candidate
evidence_use: learning_and_remediation_only
clean_reproduction_gate_eligible: false
exact_candidate_gate_eligible: false
ci_integration_gate_eligible: false
```

Those values are invariant even for a qualifying, completed external pilot.
For the Sprint 7 empirical checkpoint, the release checker additionally
requires `subject.implementation_id: agent-assure` and compares the base
release of `subject.implementation_version` with the expected release line.
Thus `0.6.6rc1` and `0.6.6` both bind to the `0.6.6` line, while another base
version fails with a distinct blocker. The independence-review receipt binds
that same base line. The Make release path supplies its `EXPECTED_RELEASE`
explicitly.

`subject.source_revision`, `distribution_artifact_id`, and
`distribution_digest` remain exact bindings to the pre-candidate code and
artifact actually tested. They are intentionally not compared with a later RC
or stable release HEAD: this checkpoint is necessary, not sufficient, and
`exact_candidate_gate_eligible` remains false. The record cannot automatically
promote a later release or satisfy a clean-reproduction or exact-candidate CI
gate. A participant may re-engage, but a later gate requires a new evidence
record against the exact frozen candidate and must re-establish the applicable
independence conditions.
