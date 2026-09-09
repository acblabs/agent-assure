# Control Efficacy

Control efficacy asks a narrower question than candidate evaluation: did the
configured assurance controls detect the exact deterministic challenges that
were run against them?

The answer is recorded in `ControlEfficacyReport/v1`. It is bound to one
mutation campaign, one `core/v1` catalog digest, one source and suite digest,
and one authored threat-applicability manifest. The report is a finite,
catalog-relative detector test. It is not an estimate of production failure
prevalence, catalog completeness, or system safety.

## Offline Quickstart

Create the four managed quickstart assets, then run the static preflight:

```bash
agent-assure init controls-mutation --out-dir assurance-controls
agent-assure doctor controls-mutate \
  --config assurance-controls/controls-mutation.yaml
```

The scaffold contains:

- `controls-mutation.yaml`, which binds package version, catalog, operator
  selection, paths, and gate effects;
- `suite.yaml` and `runset.json`, a minimal synthetic evidence-link subject;
  and
- `threat-applicability.yaml`, an authored threat-scope declaration.

Re-running `init controls-mutation` is idempotent when all four managed files
are byte-identical. An exact partial generation is resumed by creating only
the missing managed files; a changed managed file remains a conflict and no
file is replaced. Operator selections are canonicalized lexicographically at
the configuration boundary. `doctor controls-mutate` is read-only: it
validates confined paths, schema and package compatibility, catalog identity,
operator configuration, source binding, configured catalog threat references,
and static operator applicability. Its `CM_THREAT_SCOPE` diagnostic names
references absent from the authored manifest and blocks readiness until each is
declared or its operator is removed. Doctor does not mutate the subject, invoke
an evaluator, start a campaign, or use the network.

Run the configured deterministic campaign and derive the efficacy report:

```bash
agent-assure controls mutate \
  --suite assurance-controls/suite.yaml \
  --runset assurance-controls/runset.json \
  --catalog core/v1 \
  --operator drop-material-evidence-link \
  --out assurance-controls/mutation-results

agent-assure controls efficacy \
  --config assurance-controls/controls-mutation.yaml
```

The second command validates the campaign generation while holding its shared
generation lock. By default it writes
`assurance-controls/control-efficacy/control-efficacy-report.json` and a
reviewer-facing Markdown report beside it. Use `--campaign` or `--out` only
when intentionally overriding those locations. The command rejects an output
that aliases its configuration, threat manifest, or any validated campaign
input by resolved path or file identity before it writes either report.

## Exact Ratio Semantics

The catalog detector kill ratio is stored as an exact numerator, denominator,
and state:

```text
caught / (caught + survived)
```

Only completed, applicable, verdict-bearing outcomes enter the denominator.
For control efficacy, `caught` and `survived` are verdict-bearing only when the
mutation result records a deterministic evaluator basis. A stochastic or
human-reviewed result is rejected from efficacy derivation rather than being
silently converted into a deterministic catch or survivor; those bases remain
non-verdict until a typed sufficiency artifact is supported.
The report preserves separate counts for `caught`, `survived`, `inapplicable`,
`invalid_operator`, `invalid_subject`, and `execution_error`. Invalid subjects
are therefore visible without being treated as survived challenges or hidden
inside the denominator.

When no applicable operator completed, the report records `0/0` with
`state: undefined_zero_denominator`; it never substitutes zero, one, a decimal,
or a percentage. The same exact representation is used for each invariant
family, each independence class, threat challenge coverage, and independent
threat challenge coverage.

The report also persists the catalog's canonical invariant-family list. Its
invariant-family strata must match that list exactly, including families with
zero selected outcomes. This makes omission of an empty stratum detectable
from the self-contained, digest-bound report.

All five independence strata are always present, including zero-count strata:

- `external_preexisting`;
- `third_party_contributed`;
- `first_party_precontrol`;
- `first_party_postcontrol`; and
- `unknown`.

Only the first three count as independently authored challenge coverage.
`first_party_postcontrol` and `unknown` remain visible but are excluded from
the independent threat-challenge numerator. The current built-in `core/v1`
operators are `first_party_postcontrol`, so a completed built-in campaign does
not by itself establish independent challenge coverage.

## Threat Applicability

The threat manifest makes scope an input instead of inferring it from a good
campaign result. Every threat item has an ID, an applicability state
(`applicable`, `not_applicable`, or `unknown`), a `critical` flag, and a review
date. A `not_applicable` item must also name an owner and rationale. The
manifest records the threat-source name and version, present target-control
IDs, limitations, and a canonical self-digest.

An applicable threat is counted as challenged only when a completed operator
references that threat and at least one of its target controls is declared
present. A completed challenge may be either caught or survived: threat
challenge coverage says that the category was exercised, while the operator
outcome says whether the detector responded. Keep those facts separate.

Critical operator status is derived, not maintained as a second editable
list. An operator is critical for a report when it references at least one
manifest item that is both applicable and marked critical. The report carries
the exact critical survivor IDs and critical applicable threat IDs that had no
completed challenge.

Each applicable critical threat without a completed challenge emits the stable
gate reason `CRITICAL_THREAT_UNCOVERED` with its exact threat ID. The default
profile maps this finding to `review`; it is an enforceable scope finding, not
a claim that the threat was exercised or caught.

Unknown applicability is never silently converted to applicable or
not-applicable. It remains a named threat-scope state and maps to `review` in
the default gate profile.

Catalog threat references absent from the authored manifest are not discarded.
Each operator outcome carries its complete catalog threat references, the
manifest-scoped subset, and the exact residual. The report also carries the
canonical union and count of those residual IDs. Any residual makes
`threat_scope_state` the distinct `unscoped_catalog_references` state unless a
higher-priority critical gap or unknown-applicability state applies. Ordinary
declared-but-unchallenged threats remain `gap_observed`; the two scope
conditions are therefore structurally distinguishable. Unscoped catalog
references map to `review` in the default gate profile without pretending that
an omitted category's applicability is known.

## Semantic State and Gate Decision

`semantic_state` describes the observed campaign facts:

- `survivor_observed`;
- `all_evaluated_applicable_caught`;
- `indeterminate`; or
- `not_evaluated`.

`threat_scope_state` separately describes manifest coverage. Neither value is
rewritten by policy. A `ControlEfficacyGateDecision` maps the immutable report
facts through configured effects. Surviving required and critical operators
have a non-bypassable `block` floor; their profile fields are block-only in
both the runtime model and JSON Schema. A required operator without a
verdict-bearing outcome has the same non-bypassable `block` floor.
Invalid-operator, invalid-subject, and execution-error outcomes also use a
block-only field and cannot be weakened to review, informational, or ignore.
Every remaining applicable survivor and every remaining applicable uncovered
threat is projected as an explicit finding, mapped to `review` by default.
Other scope findings may map to `block`, `review`, `informational`, or `ignore`.

The generated configuration blocks surviving required operators, surviving
critical operators, invalid or error outcomes, and required operators that
were not evaluated. Critical uncovered threats, unknown threat applicability,
and unscoped catalog references require review by default.
Gate findings use stable reason codes and retain the affected operator or
threat IDs. The decision is digest-bound to the report.

Any report writer or Markdown renderer that receives a gate decision also
requires the exact gate profile. It freshly derives the decision from the
validated report/profile pair and requires complete equality, including the
profile ID, finding order, effects, and operator/threat ID sets. A matching
`report_digest` alone is insufficient.

`controls efficacy` exits `1` for a blocking configured decision, `2` for
invalid input, and `0` for pass or review-only output. The report is still
written when its configured gate blocks so reviewers and CI can inspect the
evidence.

For advisory `ci gate`, `--fail-on-warn` turns review findings such as
`CRITICAL_THREAT_UNCOVERED` into exit `1`. Invalid/error findings remain
blocking regardless of advisory profile settings. `--fail-on-not-evaluated`
checks both independent semantic dimensions.

Efficacy evidence presence and verification strength are independent.
Evidence-packet CLI and programmatic gates require efficacy by default and use
strict verification when it is present. `--require-efficacy` remains an
explicit restatement for existing automation, while `--efficacy-policy`
supplies the separately trusted verifier policy. A packet without efficacy is
invalid by default and records `efficacy_evidence=absent`,
`efficacy_verification=strict`, and `efficacy_required=true`.

The only missing-efficacy escape hatch is
`--allow-missing-efficacy-for-migration` (or the equivalently named
programmatic argument). It is limited to an evidence packet that actually lacks
efficacy, cannot be combined with a verifier policy, an explicit requirement,
or the release profile, and labels the result
`policy_profile=non-assurance-migration`. It exists only to migrate legacy
packet consumers; its successful result is not efficacy assurance and must not
be used for a release claim.

For an efficacy-bearing release claim, use the fail-closed release-facing CI
efficacy profile:

```bash
agent-assure ci gate reports/evidence-packet.json \
  --release-profile \
  --efficacy-policy assurance-controls/controls-mutation.yaml
```

This profile accepts only evidence packets, requires present efficacy evidence
and a verifier-owned controls-mutation YAML, makes warnings and not-evaluated
findings blocking, and rejects advisory, non-verdict, and legacy-comparison
weakening flags. It is the only `ci gate` profile suitable for an
efficacy-bearing release claim. It does not authorize publication.
`make release-publish-check` first applies this profile to the separately
staged packet and verifier-owned policy under
`evidence/empirical/release-control-efficacy/`, then runs empirical readiness
and the engineering release checks. Absence of either staged input fails
closed.

Strict verification requires `--efficacy-policy` pointing to a separately
trusted controls-mutation YAML and returns `0` only for
`all_evaluated_applicable_caught`,
`all_applicable_challenged`, a passing verifier decision, and no
invalid/error or required-not-evaluated operators. Missing verifier policy or
threat scope for present efficacy evidence is invalid input with exit `2`.
The returned `GateDecision` and CLI gate message always record whether
efficacy evidence was `not_applicable`, `absent`, or `present`, whether its
verification was `not_requested`, `advisory`, or `strict`, and whether efficacy
was required.

## Evidence Packets and CI

Build a packet with both the efficacy report and the configuration used to map
its gate effects:

```bash
agent-assure packet build \
  reports/evaluation-summary.json \
  --control-efficacy assurance-controls/control-efficacy/control-efficacy-report.json \
  --efficacy-config assurance-controls/controls-mutation.yaml \
  --out reports/evidence-packet.json

agent-assure ci gate reports/evidence-packet.json \
  --efficacy-policy assurance-controls/controls-mutation.yaml
```

The two packet-build efficacy options are required together. The packet embeds the report,
the exact gate profile derived from the configuration, and a decision that must
equal a fresh derivation from that report/profile pair. It also records exact
file digests for the report and configuration. Control-challenge scope remains
separate from candidate evidence closure, so a required or critical survivor
can block packet CI without changing the candidate evaluation summary.

`ci gate` also accepts a standalone control-efficacy report. Whenever an
external verifier policy is supplied, it controls acceptance and the verifier
checks exact equality of the report's catalog digest, selected operators, and
required operators. It also compares every report field derivable from the
verifier-owned installed catalog: canonical operator and family order, operator
independence and invariant metadata, and catalog threat and target-control
mappings. When the policy is controls-mutation YAML, the verifier additionally
checks the threat-manifest digest and every manifest-derived field: threat
applicability and criticality, scoped and unscoped references, and
present-control projections. A self-consistent report therefore cannot gain
coverage or independence credit merely by repeating a trusted digest string.
Strict mode additionally requires that verifier-owned threat scope; the
packet's embedded profile and decision remain provenance and must still
validate exactly, but cannot choose the verifier's acceptance policy. A bare
gate-profile JSON can be used only with `--allow-advisory-efficacy`; it does not
carry independently pinned threat scope. It also carries no independent
selected-operator set, so the verifier sets expected selected operators equal
to the profile's required operators and rejects reports whose selected set
differs, including a selected superset.

The verifier policy and a YAML policy's referenced threat manifest must be
local, confined, singly linked regular files. Their complete lexical ancestor
chains may not contain symbolic links, junctions, or other reparse components;
a symlinked checkout root or hardlinked policy file therefore fails closed as
invalid verifier input.

Regenerate the campaign and efficacy report in CI from pinned suite, RunSet,
catalog, configuration, and manifest inputs before using the result for an
efficacy assurance claim. Gating a schema-valid committed report verifies its
internal bindings and policy projection; it does not rerun operators or attest
that the recorded campaign facts were actually executed. Protect the verifier
YAML, threat manifest, catalog selection, and CI workflow with required review
or `CODEOWNERS`.

## One-Command Demonstration

```bash
agent-assure demo assure-the-assurance \
  --out .tmp/demo/assure-the-assurance \
  --clean
```

The bundled offline demo verifies an ordinary passing baseline, the expected
detector catching a mutation under the normal control, the same mutation
surviving a deliberately weakened gate profile, and an unrelated blocking
finding being rejected as substitute detection. It writes mutation campaign
generations, the efficacy JSON and Markdown, the raw efficacy gate-profile
configuration, a packet, a reviewer-facing report, and `demo-summary.json`
with relative paths and exact artifact hashes.

The wrapper exits `0` when every expected fact is observed, including the
blocking efficacy decision. Add `--strict` to return that underlying blocking
exit instead. The prepared walkthrough in
[`assets/assure_the_assurance_walkthrough.txt`](assets/assure_the_assurance_walkthrough.txt)
labels expected output explicitly; it is not presented as an external run or
recording.

## Review Boundary

The report validates arithmetic, canonical ordering, digest bindings, state
partitions, and cross-field relationships. It cannot validate whether the
authored threat scope is complete, whether a threat was classified correctly,
or whether the finite operator catalog represents production failures. Review
the manifest, residual catalog threat references, independence strata, pending
operators, invalid/error counts, and limitations alongside the ratio.

The Markdown file is a bounded reviewer view, not the authoritative artifact.
Long ID lists are rendered with exact omitted counts and direct reviewers to
the validated JSON. If the complete view would still exceed the renderer
bound, it is truncated only at a complete line and carries an explicit notice,
the omitted-line count, and the authoritative report digest.
