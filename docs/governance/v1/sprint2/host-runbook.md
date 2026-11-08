# Successor host and architecture acceptance runbook

The host integration implements the successor protocol and the fifteen exact-byte
S2 development decisions. Engineering tests do not grant acceptance. Actual
execution requires the accountable maintainer's scoped bootstrap and signatures,
a clean native Windows capture checkout, and successful hosted CI on its exact
result commit. All times are maintainer-host UTC observations without external
attestation; SSHSIG does not establish the signing time.

## Prepare the capture checkout and review the bootstrap

First review and commit the engineering foundation as `B3`, descended from the
immutable `C2`. The host checks that its complete implementation inventory,
workflow and Makefile already match this prospective base. Preparation is not
retroactively described as governed execution. The original signed records and
v1/v2 tags must remain unchanged.

Use the [native post-v2 control setup](../README.md) to prepare a fresh
`--no-local --no-checkout` clone with an empty Git template, approved origin,
the frozen `.venv`, and the canonical 55-byte post-v2 local exclude policy.
Keep the original private roadmap local and ignored. Its accepted raw digest is
`sha256:8fc2e6e6f83b6a6ac6c27492473de8690b9360eac584131b6e8b42785f4386eb`.
Use the fixed Git, OpenSSH and Windows PowerShell identities required by the
native launcher. Do not substitute the older accepted host's local excludes.

Authenticate and review `scripts/v1_s1_governance.ps1` and its legacy Python
entry point through an external trusted channel before executing them. A script
checking its own hash is not a trust root. The existing launcher authenticates
the signed successor bootstrap before loading any new module; every module and
schema byte is checked before any new module executes.

The following ordinary Python commands prepare unsigned review material only:

```powershell
$Run = '.tmp/s1-acceptance/successor-v3/ceremony-001'
& .venv/Scripts/python.exe -m scripts.v1_successor_host profile-template --out "$Run/profile"
# Review and edit profile/profile.json, including the deliberately empty capacity.
& .venv/Scripts/python.exe -m scripts.v1_successor_host plan-bootstrap --profile "$Run/profile/profile.json" --out "$Run/bootstrap"
```

The human must explicitly adopt the roles, competence scopes, capacity, conflicts,
key scope and at-most-30-day validity interval. The supported mode is
`maintainer_development` with `NO_INDEPENDENT_REVIEW`; key possession does not
establish independent mathematical or schema-review competence. The bootstrap
also binds the capture checkout's absolute root and pinned tool identities.

## Exact-byte signing and request transport

Every signing directory contains readable `claim.json`, exact raw `claim`, and
`request.json` describing the namespace and byte digest. Review the JSON and
request, then have the human sign the raw `claim` with their existing private
key, outside the agent. For example, the human's signing command uses
`ssh-keygen -Y sign -n agent-assure-governance-v1 -f <human-key> <directory>/claim`.
Never sign a reserialized JSON file or change a claim after signing. The host
does not read private keys or generate human signatures.

Wrap the resulting public LF-armored `claim.sig`:

```powershell
& .venv/Scripts/python.exe -m scripts.v1_successor_host wrap-signature --claim "$Run/bootstrap/claim.json" --signature "$Run/bootstrap/claim.sig" --out "$Run/bootstrap-signed"
```

This emits `document.json` and `envelope.json`, without asserting validity.
Use the document for bootstrap or human-decision inputs; use the envelope for
kickoff, aggregate receipt, or tag import. The frozen host verifies each signature.

Requests are closed JSON objects defined in
[the host schema](s1-successor-host.schema.json). Unknown fields fail. Write UTF-8
without a BOM; Windows PowerShell 5.1 `Set-Content -Encoding UTF8` adds a BOM.
For example, use `[IO.File]::WriteAllText($Path, $Json,
[Text.UTF8Encoding]::new($false))`. Use a fresh output directory for each action.
Outputs are bounded, private, no-clobber files under the run prefix.

Invoke each request through the existing frozen launcher:

```powershell
& 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe' -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/v1_s1_governance.ps1 successor --repository-root . --bootstrap "$Run/bootstrap-signed/document.json" --request "$Run/request.json"
```

`make v1-successor` provides the same entry with `V1_SUCCESSOR_BOOTSTRAP` and
`V1_SUCCESSOR_REQUEST`. Direct Python invocation has no accepting route.

## Prospective kickoff, result and forecast

1. Submit `kickoff-plan` with exact `base_commit=B3`, `allowed_paths`, positive
   `work_limits`, and `out`. Include
   `docs/governance/v1/sprint2/successor-start.json` in the prospective scope.
   The limits bound changed-file count, added/deleted lines and observed work
   seconds. Review/sign the generated claim, wrap its public signature, and
   submit `kickoff-import` with `claim`, `signature_envelope`, and fresh `out`.
   Retain its `kickoff-import.json`.
2. Submit `start-work` with that `kickoff` path and `out`. It records a private
   `work-start.json` and the scoped public start marker. Make only the authorized
   changes and commit exact `R3`, a proper non-merge descendant of `B3` and `C2`.
   The committed start marker permits an honest nonempty result when the reviewed
   foundation already contains the implementation. No earlier work is backdated.
3. Submit `observe-result` with `kickoff`, `work_start`, `result_commit=R3`, and
   `out` before publishing R3 for hosted CI. Retain `result-observation.json`.
   The host independently checks real Git paths, line counts, ancestry and
   observed work interval; commit timestamps are not authorization evidence.
4. Submit `forecast-plan` with `kickoff`, `result_commit`, local `roadmap` path,
   and `out`. Review all ticket/occurrence estimates and the six exact current
   ADR scopes. Future unresolved dispatch scopes are not zero work. Edit the
   proposed `human_estimates` and their rationales as needed, then use
   `forecast-recalculate` with `claim` and new `out` to recompute the summary.
5. Use ordinary `decision-plan --claim <pending-claim.json> --out <fresh-dir>`
   to prepare the selected producer decision for human signing. Sign/wrap it.
   Submit `forecast-acceptance-plan` with `producer_document` and `out`, then
   prepare, sign and wrap that separate maintainer acceptance the same way.

The forecast recomputes the original full authoring ledger from the pinned
private source and current machine inventory. Selected engineering P50/P90
quantiles use the explicitly stated common-rank model; reviewer P50 remains
separate. There is no combined P90 or calendar guarantee. These subjective
planning estimates are not empirically calibrated confidence statements.
The producer includes the closed `delivery-forecast/v1` successor projection;
its original issue/expiry interval is preserved when estimates are recalculated.
The separate maintainer acceptance binds that record's digest as well as the
producer decision. See the [compatibility contract](forecast-compatibility.md).

## Collect and close the successor

Publish R3 and obtain its same-repository push CI run through the normal human
workflow. The adapter never pushes, dispatches a workflow or sends a message.
Use a freshly allocated output for the native current `/4` capture and local
checks. The native suite and exact Makefile check expansion must all pass.
Native totals must account for every collected test as passed or skipped, with
at least one pass and zero failures, errors or deselections. Skipped tests remain
reported as skipped. Partial runs and altered check recipes cannot satisfy closure;
each required hosted CI job must complete successfully.

Submit `collect` with `kickoff`, `result_observation`, `roadmap`, `native_dir`,
`checks_dir`, `forecast_producer`, `forecast_acceptance`, integer `run_id`,
integer `run_attempt`, and `out`. `native_dir` uses the native
`.tmp/s1-acceptance/post-v2-control-<id>` allocation;
`checks_dir` uses fresh `.tmp/s1-acceptance/v3-checks-<id>`.
Supply `--ci-token-environment <EXPLICIT_VARIABLE_NAME>` only for this action.
The selected credential must remain valid through the native/local checks and
final CI read-back. The HTTP timeout starts when read-back begins. The token
stays in memory; the fixed-host HTTPS adapter rejects redirects and
checks the exact SHA, workflow bytes, attempt, and all 21 required job instances.
Child execution uses bounded logs, time and process-tree termination. Failed
local checks retain diagnostics and do not emit passing evidence.
The reviewed expansion pins the native Ruff executable separately from Python
site-packages, holds its path lease throughout execution, rejects finder fallback,
and rechecks that identity when admitting the retained local check ledger.

Collection emits `evidence.json`, `pending-receipt.json`, and aggregate signing
material. Review and sign that aggregate; submit `receipt-import` with the
`collection` directory, its `signature_envelope`, and `out`. This revalidates
the original witnesses and creates receipt-only `C3` as a Git object. It does
not move HEAD, modify the index, or replace the clean retained R3 checkout.
Its only changed path is `s1-successor-acceptance.json` in this directory.

Submit `tag-plan` with `accepted_receipt`, `evidence`, and `out`; sign its exact
raw claim. Submit `tag-finalize` with `tag_claim`, `signature_envelope`, the same
`accepted_receipt` and `evidence`, and `out` within the stated deadline (at most
one hour). A compare-and-swap creates only the fixed local v3 annotated tag.
Conflicting existing tags and late idempotent reuse fail. No remote tag is pushed.

Submit `publication-plan` with the resulting `publication-observation.json` as
`publication` and fresh `out`. Prepare its decision with `decision-plan`, then
have the human review, sign and wrap the observation countersignature. This
binds the original publication/read-back observations without inventing an
SSHSIG signing time or an independently attested clock.

Submit `verify` with `accepted_receipt`, `evidence`, the signed publication
`document.json` as `publication`, and a fresh direct run `out` such as
`.tmp/s1-acceptance/successor-v3/verify-001`. The host creates an actual standalone
no-local C3 clone and empty template, copies and verifies the frozen runtime,
and executes the authenticated launcher there. Retain the original clean R3
capture checkout, local private witnesses, frozen host and bootstrap: replay
revalidates those original sources. This is not a portable proof independent of
that retained capture host. Successful verification emits `verification.json`.
The pinned Git for Windows limits the source and destination absolute `.git`
paths to 220 UTF-8 bytes; an overlong destination fails before directory
allocation. Choose a sufficiently short capture root and run identifier.
Long working-tree file paths are enabled
explicitly for clone, checkout and inspection.

## Accept and verify the architecture bundle

Submit `s2-plan` with `successor_verification=<verification.json>` and fresh
`out`. It performs another real standalone successor replay and binds immutable
tested R3 artifacts. Review all fifteen `signing-00` through `signing-14`
claims: six drafting decisions, six design decisions, support policy, product
metric policy, and the aggregate bundle. Have the human sign each raw `claim`.

```powershell
& .venv/Scripts/python.exe -m scripts.v1_successor_host assemble-s2 --plan "$Run/s2-plan/plan.json" --out "$Run/s2-signatures"
```

Submit `s2-import` with `plan`, `signed_decisions=<documents.json>`, and fresh
`out`. Submit `s2-verify` with the resulting `accepted-bundle.json` as `bundle`
and `successor_verification`. Each route performs fresh successor execution,
checks every human signature and exact source digest, and rejects unsigned or
stale subjects. Only this trusted route can establish scoped S2 development
acceptance. Draft integrity commands continue to report `accepted=false`.

Development acceptance does not qualify a method, production writer or release.
The package remains `0.7.0`, writer `0.6.6`; this is the noninstallable `1.0.0a2`
architecture milestone. Independent admission and later implementation retain
their separate roadmap gates.
