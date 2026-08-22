# Evidence Packets

Evidence packets summarize deterministic fixture-mode evidence for CI and
release review. A packet contains an evaluation summary, an optional comparison
summary, optional control-efficacy evidence with its exact gate profile and
derived decision, an optional controlled evidence-sensitivity report, measured
usage evidence when observed, a machine-readable
interpretation section, local environment metadata, deterministic SHA-256
digests of the summary/report files used to build it, semantic and exact-file
digest bindings to a separately persisted assurance evidence graph, a
dependency-inventory digest, a release artifact manifest, and explicit
limitations.

```bash
agent-assure packet build \
  .tmp/showcase/evidence-report/evaluation-summary.json \
  --comparison .tmp/showcase/comparison-report/comparison-summary.json \
  --control-efficacy assurance-controls/control-efficacy/control-efficacy-report.json \
  --efficacy-config assurance-controls/controls-mutation.yaml \
  --evidence-sensitivity .tmp/evidence-sensitivity/evidence-sensitivity.json \
  --out .tmp/showcase/evidence-packet.json
agent-assure ci gate .tmp/showcase/evidence-packet.json \
  --efficacy-policy assurance-controls/controls-mutation.yaml
```

`packet build` also writes `evidence-packet.md`,
`assurance-evidence-graph.json`, `dependency-inventory.json`, and
`release-artifact-manifest.json` beside the JSON packet unless explicit output
paths are provided. For a known failing candidate, the CI gate is expected to
exit `1` after reading the packet.

The dependency inventory is a best-effort runtime package listing generated
from the active Python environment. Release bundles additionally write an SBOM
that records package URLs for installed packages and SHA-256 hashes for the
built wheel and source distribution. Neither artifact is a vulnerability
assessment or supply-chain attestation.

`--control-efficacy` and `--efficacy-config` are optional but inseparable. The
report contributes catalog-relative semantic evidence. The configuration maps
that immutable evidence through the authored required catalog, required
operators, and gate effects. Packet validation requires the nested report,
profile, and decision to be present together, re-derives the expected decision
from the report/profile pair, and requires exact equality. It also requires
exactly one report-file digest with role `control-efficacy-report` and exactly
one typed configuration-file digest: `control-efficacy-onboarding-config` for
authored workflow YAML or `control-efficacy-gate-profile` for a bare profile
JSON file. Packet construction parses and hashes each efficacy input from one
bounded file snapshot; the packet digest and release-manifest entry therefore
identify the exact bytes that produced the nested evidence and policy.

A current packet requires every nested persisted artifact covered by the
packet writer schema to use the packet's current schema version; independently
versioned usage artifacts retain their own emitted version. Coherent legacy
packets remain readable through their matching frozen schemas. Before writing,
the packet writer revalidates the redacted payload against the schema selected
by the packet root version—the pinned current writer schema for current output
or the matching frozen schema for supported legacy output. A mixed-version
packet therefore fails before packet bytes are created.

The v0.6.4 comparison contract requires canonical digests for both compared
RunSets. Packet construction requires the comparison candidate RunSet ID to
match the evaluation RunSet ID and rejects unequal candidate digests when the
evaluation also carries an authenticated digest. An evaluation without a
digest remains explicitly unbound; the packet never invents one from the
comparison. Frozen comparison summaries through v0.6.3 remain digestless.
Legacy readability does not imply CI acceptance: a standalone legacy
comparison or a comparison-bearing packet with either comparison digest absent
is invalid with exit `2` by default. This closes an ID-only downgrade in which
a schema-valid legacy comparison can share the evaluation's display ID while
referring to unauthenticated bytes. A verifier that must retain this historical
behavior can opt in explicitly with `--allow-legacy-unbound-comparison`; the
compatibility use is recorded in the decision message. Supplying the override
for a packet without a comparison or for an already digest-bound comparison is
itself invalid, so the exception cannot be enabled speculatively across all
artifacts. The override applies only after normal frozen-schema and model
validation and does not weaken artifact loading.

`control-efficacy-onboarding-config` identifies the exact controls-mutation
onboarding YAML supplied to `packet build --efficacy-config`.
Packet construction also loads that configuration's confined threat manifest
from one file snapshot and requires its manifest digest to match the embedded
report before publishing any packet outputs.
`control-efficacy-gate-profile` identifies a standalone gate-profile JSON file,
as used by the packaged demo. A current packet must contain exactly one of these
roles and rejects the ambiguous `control-efficacy-config` role, so consumers do
not have to infer the policy shape from a file name or untyped digest.

The Markdown packet renders this material under **Assurance Control
Challenge**, not under candidate evidence closure. It includes the catalog,
semantic state, policy mapping, exact detector ratio, required and critical
survivor counts, threat-category counts, independent challenge counts, and
gate findings. A candidate evaluation may pass while the efficacy decision
fails; packet CI treats that required-control failure as blocking without
rewriting the candidate evaluation facts.

`--evidence-sensitivity` is optional in the producer schema. When present,
packet construction parses and hashes the report from one bounded snapshot and
carries the complete self-digested report. The report's counterfactual RunSet ID,
RunSet digest, and canonical evaluation-summary digest must exactly match the
packet evaluation. If the packet also contains a comparison, the report's
baseline and counterfactual arms must exactly match the comparison pair. The
packet and its release manifest each require exactly one raw digest role named
`evidence-sensitivity-report`; an absent nested report rejects that role.
Packet Markdown preserves the detector state, verdict role, gate effect,
endpoint, expected and observed relations, arm identities, decision inertia,
reason codes, synthetic status, and every limitation.

The packet section leads with an explicit boundary: v1 is a synthetic
declarative fixture harness/oracle, and its result is not evidence that a model
used contextual evidence instead of parametric memory.

When `ci gate` receives a packet, an invalid nested decision or other invalid
component takes precedence, followed by a blocking evaluation, comparison,
evidence-sensitivity, or efficacy decision. A responsive sensitivity report
passes its dimension; an evidence-insensitive report exits `1` with its stable
reason code. A confounded or prerequisite-unmet sensitivity report is
non-verdict evidence. Sensitivity-bearing packets fail closed as invalid with
exit `2` by default, matching the producer's refusal to claim a result. A
verifier may explicitly accept this advisory state with
`--allow-sensitivity-non-verdict`, which restores the `not_evaluated`,
exit-`0` behavior. `--fail-on-not-evaluated` instead maps it to a blocking
exit `1`. Efficacy-aware CLI gating uses strict verification by default when
efficacy evidence is present and requires a separate
verifier-owned controls-mutation YAML for that verification. Strict mode pins
catalog, operator scope, and threat-manifest digest, re-derives a verifier
decision, and accepts only complete all-caught/all-challenged evidence. The
packet's embedded profile and decision must remain exact but are producer
provenance, not the strict acceptance policy. A standalone
`control-efficacy-report` uses the same external verifier policy requirement.

For a packet carrying a release manifest, CLI gating verifies every bound
summary and graph against candidate roots rather than choosing a root from path
shape alone. It considers the packet directory for current self-contained
producer output and the enclosing source/Git root for legacy repo-relative
manifests. Exactly one distinct candidate must satisfy the full digest, parsed
model, and graph-projection checks. Two valid trees are ambiguous and fail
closed; no valid tree surfaces the binding failure. `--artifact-root` selects
one verifier-trusted root exclusively.

Presence is controlled by verifier-owned policy. `--require-efficacy` makes an
efficacy-free packet invalid, and `--efficacy-policy` implies that requirement.
Otherwise an efficacy-free packet remains eligible for ordinary
evaluation/comparison gating but explicitly reports
`efficacy_evidence=absent`, `efficacy_verification=not_requested`, and
`efficacy_required=false`; it does not claim an efficacy check occurred.
`--require-evidence-sensitivity` independently makes a sensitivity-free packet
invalid. Use that option in release automation whenever sensitivity is required;
a generic evaluation/comparison packet cannot safely infer that an omitted
report should have been present merely from shared RunSet identities. Without
the sensitivity requirement, the field remains intentionally optional for
non-RAG and legacy workflows.

`--allow-advisory-efficacy` explicitly restores transported-profile advisory
gating. In that mode, `--fail-on-not-evaluated` examines both semantic
dimensions and `--fail-on-warn` makes review findings blocking. A bare
gate-profile JSON can be supplied as an advisory verifier override, but cannot
satisfy strict mode because it does not pin a separate threat manifest. The
bare profile has no selected-operator set, so its expected selected set equals
its required set and reports with a different selected set are rejected.

Release replay cross-checks manifest-listed artifact digests when the referenced
files are available under the replay artifact root. That reproducibility check
includes the control-efficacy report and raw configuration roles and is separate
from cosign verification of exact workflow-signed blobs.

Packet artifact digests, dependency-inventory digests, and release-manifest
digests are raw SHA-256 hashes over the LF-normalized JSON files that were
written locally. They are environment-bound exact-artifact anchors, not the
cross-platform-stable JCS content digests used for suites, fixture manifests,
and runset provenance. `packet_id` is derived from the redacted summaries after
local environment metadata is excluded, plus interpretation text and
limitations. When efficacy is present, its redacted report projection and gate
profile/decision are included in packet identity. `packet_id` intentionally
excludes exact-file digests and the release manifest.

When evaluation or comparison summaries contain usage evidence, packets keep
that evidence beside governance findings. Candidate usage summaries, baseline
usage summaries, usage deltas, pricing snapshot IDs and digests, declared
estimated cost deltas, and per-cost-observation evidence are review facts only.
Missing usage is rendered as `not_observed` and does not create a failing gate.
Cheaper usage is not interpreted as a better candidate when governance evidence
regresses.

Release evidence can attach keyless cosign bundles to the packet JSON and
Markdown, packet-bound evaluation and comparison summaries, assurance evidence
graph, release artifact manifest, digest replay file, SBOM, wheel, and source
distribution.
Those signatures verify the exact bytes and workflow identity that signed them;
they do not turn packet contents into safety, compliance, clinical-validation,
live model-quality, or standards adoption evidence. See
`docs/release_evidence.md` for exact verification commands.
