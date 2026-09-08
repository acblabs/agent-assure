# External Pilot Reviewer Guide

This review turns a mechanically valid pre-review candidate into a closed
external-pilot bundle. It is a human-operator attestation bound to exact bytes;
the software does not authenticate the participant, repository owner, consent
authority, or reviewer.

The reviewer must use a pseudonym distinct from the participant, be
independent of pilot execution, and must not have executed or controlled the
participant's runs or authored the participant-supplied facts and
attestations. The reviewer does not have to be a non-maintainer. An `acblabs`
reviewer is eligible only when those facts are true; authoring the reusable kit
or workflow does not itself make that reviewer the pilot operator.

## Required Out-of-Band Checks

Obtain the candidate artifact, capture and finalization run URLs, fork URL,
participant pseudonym, each run's actual head revision, and the agreed basis
for environment control through the non-public handoff arranged after
recruitment. Derive both head revisions from the corresponding run record or
GitHub API rather than accepting a generic branch revision. Before asserting
any checklist value, verify:

- the fork and Actions environment were controlled by the non-maintainer
  participant and `acblabs` did not operate the runs;
- the capture workflow at the capture run's head revision and the finalization
  workflow at the finalization run's head revision each byte-match the
  corresponding file at the trusted upstream workflow revision named in the
  recruitment handoff;
- the private capture's `participant_repository_revision` exactly equals the
  capture run's actual head revision;
- the upstream source revision and wheel provenance match the exact captured
  bytes;
- the committed `agent-assure-pilot/participant-waiver.yaml` at the
  capture run's actual head revision matches the input-manifest
  SHA-256;
- the compiled-suite, RunSet, and complete waiver-set semantic identities
  match the input manifest;
- exact argv, input bindings, timestamps, exit code, execution evidence, and
  optional campaign output agree;
- the flat directory contains only the evidence descriptor and every declared
  artifact;
- friction and any remediation state are truthful;
- no raw input, raw command stream, credential value, direct participant
  identifier, or confidential content entered the candidate; and
- the consent record explicitly covers the evidence descriptor, the receipt
  you are about to create, and the complete declared artifact inventory.

The Stage-1 identity and run digests are privacy-minimized pseudonymous
bindings, not anonymization or proof. They remain potentially linkable to
public GitHub metadata. Use the real run and repository records supplied out
of band to confirm control and same-operator facts. The public candidate omits
those brute-forceable bindings from its bundle bytes, but it retains the random
opaque binding shared with Stage 1. The Stage 2 Actions artifact name also
contains the capture run ID. These transport and cross-stage facts can remain
linkable even though the raw GitHub identity fields are absent. The candidate's
committed-input content and semantic digests can also be matched to waiver bytes
in the public fork. Do not describe the result as “independently verified”;
the accurate description is “operator-attested review bound to exact bytes.”

## Bootstrap a Trusted Verifier

Do not install or execute the participant-supplied wheel before provenance and
static wheel validation. Obtain the captured `source_revision` from the
candidate, confirm it is the immutable execution-source revision pinned by the
trusted upstream pilot workflow, and build the verifier from a separate
upstream checkout:

```bash
git clone https://github.com/acblabs/agent-assure.git reviewer-source
git -C reviewer-source checkout --detach <captured-source-revision>
python -m venv reviewer-venv
. reviewer-venv/bin/activate
python -m pip install --require-hashes -r reviewer-source/requirements.lock
python -m pip install --no-deps --no-build-isolation -e reviewer-source
```

Use this trusted environment for the commands below. The loader validates the
candidate wheel structurally and byte-binds it without importing or executing
code from that wheel.

## Create the Receipt

Keep the review template outside the candidate directory. Copy
`docs/templates/external_pilot_independence_review.yaml`, replace every
placeholder, and set `reviewed_at` no earlier than the evidence `recorded_at`.
Assert a boolean only after completing that check.

From the candidate's parent directory, run:

```bash
agent-assure release pilot review \
  --bundle-root external-pilot-candidate \
  --evidence external-pilot-evidence.json \
  --template /tmp/external-pilot-independence-review.yaml \
  --out external-pilot-independence-review.json
```

Then verify the complete bundle against the intended release line:

```bash
python -c "from pathlib import Path; from agent_assure.pilot_bundle import load_verified_external_pilot_bundle; load_verified_external_pilot_bundle(Path('external-pilot-candidate'), evidence_path='external-pilot-evidence.json', review_receipt_path='external-pilot-independence-review.json', expected_release='0.6.6')"
```

Do not edit participant artifacts. Any changed byte invalidates the descriptor
or receipt; obtain a new candidate instead. After exact verification, the
consented directory may be copied unchanged to
`evidence/empirical/external-pilot/`. The real-model-study bundle remains a
separate release prerequisite.
