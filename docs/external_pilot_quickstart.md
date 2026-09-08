# External Pilot Quickstart

This is a two-stage GitHub Actions pilot for one person who is not an
`acblabs/agent-assure` maintainer. Target participant effort is 10–15 minutes;
the CI jobs may run longer. It uses the deterministic offline controls-mutation
workflow. No participant-supplied model/provider API key, proprietary data,
repository secret, or maintainer access is needed. GitHub supplies its normal
short-lived, read-only workflow token.

The result is privacy-filtered onboarding-learning evidence. It is not an
endorsement, adoption claim, customer testimonial, third-party audit, safety or
security assessment, or exact-candidate release validation. A failed or
blocked attempt is useful when its execution and friction facts are complete;
green output is not required.

## Before You Start

You qualify as the operator only when all of these are true:

- you are not an Agent Assure maintainer;
- you control the fork and its Actions settings;
- no `acblabs` maintainer configures, dispatches, or operates either run; and
- you can use one pseudonym and commit one benign participant-authored input.

GitHub hosting and a fork do not prove independence by themselves. A later
reviewer checks repository control out of band. `acblabs` may perform that
review only if it did not operate or alter your pilot.

Do not use your GitHub name as the pseudonym. A pseudonym reduces direct
identification; it is not anonymity. The kit rejects exact matches to the
current GitHub actor, owner, and known repository/account IDs, but it cannot
recognize every real name or identifying alias. The participant and reviewer
remain responsible for that broader check. Do not put credentials, private
data, raw prompts or outputs, direct personal identifiers, or confidential
repository content in the input or workflow fields. GitHub still retains its
ordinary account, repository, build, and workflow metadata.

Stage 1 stores a capture handoff in your fork's Actions storage for up to 14
days. In a public fork, signed-in users with repository read access may be able
to download it under GitHub's artifact-access rules. The handoff contains
linkable, pseudonymous digests of GitHub
repository, account, run, and committed-revision identifiers so Stage 2 can
fail closed on a different operator or run. The final public candidate bundle
bytes omit the raw participant revision and those brute-forceable GitHub
identity/run digests. They retain a random opaque binding shared with the
capture, so anyone who obtains both artifacts can correlate the two stages.
The capture and final candidate also preserve content and semantic digests of
the committed waiver. Those digests can be matched to the waiver bytes in the
public fork and can therefore link the candidate back to that fork. Stage 1
will not run unless you explicitly consent to the temporary handoff storage.

## Stage 1: Capture the Attempt

1. Fork `acblabs/agent-assure` directly to a repository you control and enable
   GitHub Actions in the fork.
2. Choose a pseudonym such as `participant-ember-17`. It must be 1–64
   characters, start with a letter or digit, and then use only letters,
   digits, `.`, `_`, `:`, `/`, or `-`.
3. Copy
   `docs/templates/external_pilot_participant_waiver.yaml` to
   `agent-assure-pilot/participant-waiver.yaml` in your fork.
4. Replace every `replace-participant-pseudonym` occurrence with your chosen
   pseudonym. Replace `replace-with-a-short-benign-participant-rationale` with
   your own short, printable explanation of why you are running the pilot.
   Leave `reason_code`, `finding_id`, `artifact_digest`, and `expires_on`
   unchanged. The fixed zero digest is designed and validated not to match the
   scaffold finding.
5. Commit that new file to your fork. The workflow refuses an uncommitted file
   or an unchanged template.
6. In the fork's **Actions** tab, run **external pilot 1 - capture** on the
   branch containing your commit. Enter the pseudonym. Read and accept the
   temporary-storage scope only if you consent to it, then attest environment
   control only if that statement is true.

The capture workflow builds the immutable upstream `0.6.6` source revision
pinned in the workflow,
runs one exact catalog-based `controls mutate` command, and uploads a 14-day
artifact named `external-pilot-capture-<run-id>-<attempt>`. Record the numeric
run ID and attempt number from the run page.

The action persists the tested wheel, exact input and semantic digests,
privacy-filtered runner metadata, linkable pseudonymous repository/run bindings,
exact argv, timestamps, exit code, and—only for evidence-bearing exit `0` or
`1`—the schema-valid campaign output. It discards command stdout/stderr and
does not copy the authored waiver, suite, or RunSet into the capture.

Download and inspect the capture artifact before continuing. Keep the run URL
and your fork available so the reviewer can verify the committed input bytes
and environment control out of band.

## Stage 2: Record Friction and Consent

Run **external pilot 2 - finalize** from the same fork and with the same GitHub
account. Supply the capture run ID and attempt number.

- Select `no_friction_observed` only if installation, configuration,
  diagnostics, CI execution, runtime, and the instructions caused no material
  onboarding friction.
- Otherwise select `friction_observed` and its primary category. The candidate
  will honestly record a planned onboarding remediation and remain gated until
  an applicable remediation is actually applied and reviewed.
- Re-attest environment control only if the original statement remains true.
- Grant publication only if you prospectively authorize the outcome-dependent
  privacy-filtered scope below: the evidence descriptor, the later byte-bound
  review receipt, and every artifact enumerated by the generated consent
  record. This authorizes the named scope before the descriptor and receipt
  bytes exist; it does not claim that you reviewed those final bytes. It also
  authorizes up to 14 days of candidate storage in the public fork's Actions
  artifacts under GitHub repository read-access rules. The artifact name
  includes the capture run ID, and the candidate bytes share the capture's
  random opaque binding, so possession of both stages permits correlation.
  The committed-input digests can also be matched to the public fork's waiver
  bytes.
- Declining is allowed. Stop after Stage 1 or leave the publication box
  unchecked; Stage 2 then produces no public candidate.

For a completed, no-friction attempt, the candidate inventory is:

- `external-pilot-evidence.json`;
- the later `external-pilot-independence-review.json` receipt;
- the exact tested wheel;
- `environment-manifest.json`;
- `environment-control-evidence.json`;
- `input-manifest.json`;
- `command-execution-evidence.json`;
- `assurance-mutation-campaign.json`;
- `friction-assessment.json`; and
- `publication-consent.json`.

A non-completing attempt omits the campaign output. An observed-friction
candidate adds `remediation-record.json`. The consent record enumerates the
actual inventory, including itself, before the evidence descriptor is built.

The second run uploads a mechanically verified, closed pre-review candidate
named `external-pilot-candidate-<capture-run-id>-<attempt>`. Its descriptor may
truthfully mark the execution as an external attempt, but without the review
receipt it is not yet a verified, publish-ready empirical-checkpoint bundle
and does not satisfy the repository publish gate.

Reply `interested` on the recruitment issue without posting run or fork URLs.
The maintainer will arrange a non-public coordination channel for the two run
URLs, the candidate artifact, and both runs' actual head revisions. Never paste
identities, raw input content, or private handoff details into the public issue.

## What Happens Next

The reviewer follows the [external pilot review guide](external_pilot_review.md),
checks the exact bytes and manual trust facts, and creates the sole missing
review receipt. Even a verified external pilot does not by itself authorize a
release: the separately preregistered real-model study is still mandatory.
