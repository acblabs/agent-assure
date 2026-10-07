# agent-assure

## Output equivalence is not process equivalence.

**Same approval. Missing evidence link. Configured CI gate blocked.**

`agent-assure` catches regressions in declared, structured process evidence that
final-answer-only checks can miss. It turns privacy-filtered run records into
reproducible comparisons, reviewer-facing artifacts, portable evidence packets,
and ordinary CI gate signals. Evidence strength follows its recorded origin:
fixture values are authored test inputs, instrumented-adapter values remain
producer-attested, and direct model responses do not independently prove that a
tool, evidence lookup, policy check, or human review occurred.

**Local-first · offline flagship demo · versioned artifacts · CI-native · no
hosted control plane required**

<p align="center">
  <a href="#quickstart"><strong>Run the offline demo</strong></a> &middot;
  <a href="#actual-reviewer-output"><strong>Inspect the reviewer output</strong></a>
</p>

<p align="center">
  <a href="docs/for_ai_leaders.md">For AI leaders</a> &middot;
  <a href="docs/architecture.md">For architects</a> &middot;
  <a href="docs/for_engineers.md">For engineers</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/agent-assure/"><img src="https://img.shields.io/pypi/v/agent-assure?style=flat-square&color=0f766e" alt="PyPI version"></a>
  <a href="https://pypi.org/project/agent-assure/"><img src="https://img.shields.io/pypi/pyversions/agent-assure?style=flat-square&color=536171" alt="Supported Python versions"></a>
  <a href="https://github.com/acblabs/agent-assure/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/acblabs/agent-assure/ci.yml?branch=main&style=flat-square&label=ci" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-166534?style=flat-square" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/status-RC-8a5a00?style=flat-square" alt="Project status: Release candidate">
</p>

<img src="docs/assets/flagship-evidence.svg"
     alt="Bundled deterministic flagship fixture: across ten cases, zero recommendation or outcome fields change; in the highlighted case, baseline and candidate both approve, but the candidate loses the claim-duration evidence link, producing a new-failure classification and a blocked configured CI gate."
     width="100%">

`10 deterministic fixture cases` · `0 decision fields changed` ·
`claim-duration: linked → missing` · `classification: new_failure` ·
`configured CI gate: blocked`

> [!NOTE]
> This is a bundled deterministic fixture demonstration, not a model benchmark,
> live-model result, or customer outcome. It requires no provider API key,
> network call, or token spend.

[Read the flagship demonstration](docs/demo_flagship.md)

## Choose your path

| Your role | Start with the question that matters |
| --- | --- |
| **Chief AI Officers and release owners** | Did a release preserve its declared controls? See the local evidence and portable handoff for repeatable review. [Read the AI leader brief](docs/for_ai_leaders.md). |
| **AI/ML architects and platform owners** | Where does it fit, what crosses the trust boundary, and which contracts are stable? [Review the architecture](docs/architecture.md) · [Inspect the API surface](docs/api_surface.md). |
| **AI/ML engineers** | How do I turn observable expectations and privacy-filtered run records into a configured CI decision? [Follow the engineering guide](docs/for_engineers.md). |

## What it can surface

A final-answer-only check can see no decision-field change while a declared
release expectation regresses:

- **Evidence and RAG support:** a required source or material claim-to-evidence
  link disappears, or declared corpus and retrieval identity changes. Example:
  `MATERIAL_CLAIM_MISSING_EVIDENCE → new_failure`. The development surface
  also includes an authority-scoped, deterministic
  [controlled evidence-sensitivity contract](docs/evidence_sensitivity.md).
  Its v1 producer is a declarative synthetic fixture harness, not evidence that
  a model used contextual evidence instead of parametric memory. A separate
  [repeated paired protocol](docs/repeated_evidence_sensitivity.md) supports the
  same narrow binary response relation for prebound stochastic live studies.
  Its fixed planned-frame composite rate includes every frozen cluster,
  pessimistically scores a non-analyzable cluster as zero, and reports
  observed/analyzable counts separately. Verdict-bearing packets and graphs bind
  the exact candidate RunSet, while both source execution configurations remain
  anchored to their predeclared arms. Conclusions remain conditional on
  statistical sufficiency, exact subject binding, and declared cluster
  assumptions. The untagged development surface also provides a
  [preregistered real-model study workflow](docs/real_model_study.md), but this
  repository contains no real-provider study result.
- **Human review:** a required route or performed-review record is missing.
- **Provider, tool, and privacy boundaries:** a forbidden provider or tool
  appears, or declared route, redaction state, or detector identity changes.
- **Usage and reliability:** retries, tool calls, tokens, latency, rate-limit
  events, or declared estimated cost change materially.
- **Streaming integrity:** events are replayed, duplicated, conflicting, or
  outside the declared sequence contract.
- **Protocol-bound live behavior:** repeated observations drift outside a
  declared protocol or comparison boundary, or a paired evidence-response
  study is underpowered, structurally invalid, or inconsistent with its exact
  pre-execution arm bindings.

A surfaced difference may be blocking, review-only, or informational. Usage
and reliability deltas block only when a suite or policy declares that
behavior.

## Quickstart

Requires Python 3.11 or newer. The release-qualified matrix is the full suite
on Ubuntu 24.04 with Python 3.11 through 3.14, plus the native containment
subset on Windows Server 2025 with Python 3.11 and 3.14. macOS is not currently
CI-qualified. The five hashed `requirements*.lock` files are the dependency
sets exercised for release; the broader ranges in `pyproject.toml` express
compatibility intent, not exhaustive version-combination qualification.

```bash
pip install agent-assure==0.6.5
agent-assure demo flagship --out .tmp/demo/flagship --clean
```

The installed package runs the bundled deterministic fixture from any
directory—no repository clone, provider API key, network call, or token spend.

```text
output equivalence: preserved
missing evidence link: claim-duration
reason code: MATERIAL_CLAIM_MISSING_EVIDENCE
classification: new_failure
CI gate: blocked as expected
```

The demo wrapper exits `0` only when it verifies that the expected regression
was caught. The underlying candidate evaluation, comparison, and CI commands
remain strict and exit nonzero for the blocking finding.

### Actual reviewer output

<a href="docs/assets/flagship-evidence-diff.png">
  <img src="docs/assets/flagship-evidence-diff.png"
       alt="Screenshot of the generated Agent Assure evidence-diff report. It shows the preserved approval, zero changed decision fields, the missing claim-duration evidence link, and the blocked configured CI gate."
       width="100%">
</a>

<p align="center"><sub>Screenshot of the reviewer-facing
<code>evidence-diff.html</code> produced from the same bundled fixture. Open the
image to inspect it at full resolution.</sub></p>

### Reviewer-facing artifacts

Key artifacts are written under `.tmp/demo/flagship`:

| Artifact | Review purpose |
| --- | --- |
| `demo-summary.json` | Machine-readable demonstration result |
| `baseline-report/evaluation-summary.json` | Baseline behavior against declared expectations |
| `comparison-report/comparison-summary.json` | Controlled baseline-to-candidate classification |
| `ci-report/evidence-packet.json` | Portable machine-readable review handoff |
| `evidence-diff.html` | Self-contained human-readable evidence diff |

<details>
<summary><strong>How this README evidence view is verified against the fixtures</strong></summary>

### Flagship regression at a glance

This diagram is checked in CI against the bundled flagship fixtures, keeping
README claims aligned with the evidence produced by the project itself.

```mermaid
flowchart LR
    subgraph OutputCheck["Ordinary visible-output check"]
        BOut["Baseline output<br/>recommendation=approve<br/>outcome=approve"]
        COut["Candidate output<br/>recommendation=approve<br/>outcome=approve"]
        Same["Visible answer unchanged"]
        BOut --> Same
        COut --> Same
    end

    subgraph InvariantCheck["agent-assure invariant check"]
        BEv["Baseline evidence<br/>claim-duration linked"]
        CEv["Candidate evidence<br/>claim-duration missing link"]
        Pass["Baseline evaluation: pass"]
        Fail["Candidate evaluation: fail<br/>MATERIAL_CLAIM_MISSING_EVIDENCE"]
        BEv --> Pass
        CEv --> Fail
    end

    Same --> Tension["Output unchanged<br/>but governance invariant regressed"]
    Equiv["Fixture equivalence: pass"] --> Compare["Baseline-to-candidate comparison"]
    Pass --> Compare
    Fail --> Compare
    Tension --> Compare

    Compare --> NewFailure["Classification: new_failure"]
```

</details>

## Where it fits

`agent-assure` complements the evaluation, observability, runtime-control, and
governance systems teams already use.

| Layer | Primary question | Relationship to `agent-assure` |
| --- | --- | --- |
| **Output and agent evals** | Does the answer, trajectory, tool use, or component meet its quality criteria? | Adds source-aware checks for declared process-evidence expectations. |
| **Observability and tracing** | What happened during execution? | Consumes versioned, privacy-filtered evidence; it is not a telemetry backend. |
| **Runtime guardrails** | What must change or stop during a request? | Evaluates at release time; it is not runtime enforcement. |
| **Governance and GRC systems** | Which policies, approvals, and accountabilities apply? | Supplies review evidence; it is not a system of record and does not determine compliance. |
| **`agent-assure`** | Did a controlled candidate preserve declared process expectations? | Evaluates, compares when equivalent, packetizes, and returns a CI signal. |

It is a particularly strong fit when release review must be local,
reproducible, CI-enforceable, and traceable without a required hosted control
plane.

## How it works

```text
Declare → Capture from a declared source (privacy-filtered) → Evaluate
        → Compare (when equivalent) → Packet → Gate
```

Declared expectations and canonical run evidence remain distinct. The
candidate is evaluated first; equivalent-baseline context is added only after
comparison prerequisites pass. The evidence packet then supports a CI signal
and human release review.

`agent-assure` is a local-first Agent Release Assurance Compiler: controls and
evidence stay bound to method identity, prerequisites, provenance, assumptions,
and limitations.

<img src="docs/assets/local-assurance-lifecycle.svg"
     alt="A declared suite with expectations and canonical baseline and candidate run records enter a local assurance boundary. Invariant evaluation and fixture-equivalent comparison produce an evidence packet for a configured CI gate and human release or governance review."
     width="100%">

The assurance model is deliberately bounded:

- **Deterministic and reproducible in fixture mode:** fixed, versioned fixtures,
  canonical serialization, schemas, and digest-bound manifests make checks
  repeatable; that reproducibility does not estimate production prevalence.
- **Scoped invariance claims:** results cover only declared, observable fields
  and explicit prerequisites—not hidden reasoning or all production behavior.
- **Traceable lineage:** expectations connect to RunSets, findings, comparisons,
  evidence packets, and configured gate state; provenance records participating
  material.
- **Fail-closed:** malformed, conflicting, incompatible, ambiguous, or unbound
  evidence does not silently become a passing review.
- **Statistically bounded:** live conclusions about probabilistic provider
  behavior remain tied to a declared statistical protocol, with its data
  boundary, configuration, window, sampling noise, dependence, and limitations
  explicit.

Architecture choices and evidence boundaries are documented in
[architectural decision records (ADRs)](docs/adr/), including deterministic
fixture versus stochastic live semantics.

## Challenge the assurance controls

The development-RFC `core/v1` mutation catalog runs seven deterministic
challenges across evidence linkage, human-review routing, tool boundaries,
provenance identity, privacy redaction, duplicate replay, and budget-stop
integrity:

```bash
agent-assure controls mutate \
  --suite assurance/suite.yaml \
  --runset runs/baseline.json \
  --catalog core/v1 \
  --seed 0 \
  --today 2026-08-02 \
  --full-report \
  --out reports/control-challenge
```

Every selected operator runs independently against the same immutable source.
The output binds the canonical catalog digest, normative expected detector,
observed and prohibited substitute findings, exact changed paths, provenance,
independence class, seed, and limitations. The campaign itself remains a
finite challenge record. `controls efficacy` can derive an exact
catalog-relative detector kill ratio over completed applicable outcomes while
preserving inapplicable, invalid, and error counts outside its denominator.
That ratio is not a safety score, statistical confidence interval, or
universal-coverage claim.

Only deterministic `caught` and `survived` campaign outcomes may contribute a
control-efficacy verdict. An applicable critical threat with no completed
challenge emits `CRITICAL_THREAT_UNCOVERED` and requires review under the
default profile. Required and critical survivors, invalid/error outcomes, and
required non-verdict outcomes are always blocking. Evidence-packet `ci gate`
requires control-efficacy evidence by default and uses strict verification when
it is present; pass a verifier-owned controls-mutation YAML with
`--efficacy-policy`. `--require-efficacy` remains as an explicit restatement
for existing automation. Strict CI accepts only complete, all-caught,
all-applicable-challenged evidence and pins the catalog, selected and required
operators, and threat manifest. The conspicuous
`--allow-missing-efficacy-for-migration` escape hatch is only for temporary
non-assurance migration and records that weaker profile. Use
`--allow-advisory-efficacy` only for an explicit review flow with evidence
present.

For an efficacy-bearing release claim, `ci gate --release-profile` additionally
requires an evidence packet, a verifier-owned `--efficacy-policy`, present
efficacy evidence, and blocking warning/not-evaluated handling. It rejects the
advisory and compatibility weakening flags. This is a CI efficacy profile, not
publication authorization. `make release-publish-check` runs that strict
profile against the separately staged release efficacy packet and verifier
policy before the empirical-readiness and engineering release checks; all are
necessary, and none alone authorizes publication.

The packaged offline demonstration exercises both a strong and deliberately
weakened assurance control, then verifies that an unrelated failure cannot
substitute for the expected detector:

```bash
agent-assure demo assure-the-assurance \
  --out .tmp/demo/assure-the-assurance \
  --clean
```

For a minimal editable workflow, start with `agent-assure init
controls-mutation`, run the read-only `doctor controls-mutate` preflight, then
produce a campaign and `control-efficacy-report.json`.

[Inspect the exact seven-operator catalog](docs/mutation_catalog.md) ·
[Measure control efficacy](docs/control_efficacy.md) ·
[Read "Who assures the assurance?"](docs/posts/who_assures_the_assurance.md) ·
[Review the evidence contracts](docs/evidence_carrying_releases.md)

## Integrate your agent

`agent-assure` integrates through declared YAML expectations, versioned run
evidence, the documented CLI, and the framework-neutral `AgentRunRecord`
producer contract.

| You provide | `agent-assure` does | You receive |
| --- | --- | --- |
| Declared expectations, a candidate RunSet, and an optional equivalent baseline RunSet | Validate, evaluate, compare when equivalence prerequisites pass, packetize, and apply the configured gate | Evaluation and comparison summaries, `evidence-packet.json`, human-readable reports, and an ordinary CI exit status |

The integration contract has three parts:

1. Declare structured process-evidence expectations in YAML.
2. Produce versioned run records from fixtures or privacy-filtered adapters with
   explicit field origins.
3. Evaluate the candidate, compare equivalent baseline evidence when available,
   and gate the resulting evidence packet.

A real expectation from the bundled flagship suite:

```yaml
cases:
  - case_id: shared-source-multi-claim
    fixture_id: shared-source-multi-claim
    expectation:
      expected_recommendation: approve
      required_evidence_refs:
        - ref-shared-clinical-note
      material_claim_ids:
        - claim-eligibility
        - claim-duration
```

`agent-assure` does not infer material claims from rationale text. Authors
declare the oracle, and run-record producers emit explicit claim-to-evidence
links for the material claims they intend to satisfy.

[Author expectations](docs/expectation_authoring.md) ·
[Understand the CLI contract](docs/cli_contract.md) ·
[Review the public API surface](docs/api_surface.md) ·
[Understand evidence packets](docs/evidence_packets.md)

### GitHub Actions example using the bundled fixture

Pin the runner image, GitHub-owned actions, package, and composite action in
release workflows. This runnable example stays on v0.6.5, the latest published
release. The stricter v0.7.0 action contract described below remains unavailable
until v0.7.0 is published. Replace the example suite and variant paths with your
own controlled materials.

```yaml
name: agent-assure
on: [pull_request]

permissions:
  contents: read

jobs:
  assure:
    runs-on: ubuntu-24.04
    steps:
      # actions/checkout@v7.0.1
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      # actions/setup-python@v7.0.0
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97
        with:
          python-version: "3.11"
      - run: python -m pip install agent-assure==0.6.5
      # agent-assure v0.6.5
      - uses: acblabs/agent-assure/.github/actions/agent-assure@18bef8be4117c75268c67ede8cf781daaf75b893
        with:
          suite: examples/prior_auth_synthetic/suite.yaml
          baseline-variant: examples/prior_auth_synthetic/variants/baseline.yaml
          candidate-variant: examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml
          report-mode: full
          upload-reports: "true"
```

`full` produces the complete review artifacts; `fail-fast` gives shorter
blocking feedback. The pinned v0.6.5 example uses only inputs available in that
published action. Its bundled fixture invocation is explicitly a non-assurance
smoke example, not evidence of control efficacy. The unreleased v0.7.0
candidate composite action has two mutually exclusive paths. Its strict path
requires both `control-efficacy-report` and `efficacy-policy`, rebuilds the
current evaluation packet with that report, and strictly re-verifies it against
the separately trusted policy. Repository CI qualifies that strict path on a
hosted Ubuntu runner with a deterministic passing efficacy campaign and repeats
the strict packet gate; a separate runner job retains the explicitly labeled
non-assurance migration smoke. This qualifies action behavior, not the
independence of production evidence. Keep the production policy under verifier
control (for example, in a separately protected checkout placed beneath
`GITHUB_WORKSPACE`); a policy supplied by the candidate is not independent
authority. Fixture-only, evaluation-only jobs must instead opt into
`allow-missing-efficacy-for-migration: "true"`, which remains a labeled
non-assurance result. Omitting both paths, supplying only one strict input, or
combining strict inputs with the migration flag fails closed. Baseline-bearing
runs remain blocking for both `new_failure` and `persistent_failure`
dispositions; an exact waiver does not authorize either comparison result. The
v0.7.0 action accepts `out-dir` only as a strict descendant of
`GITHUB_WORKSPACE` or `RUNNER_TEMP` and rejects traversal, roots, and
linked/reparse-point ancestors. Strict efficacy mode further requires the
output beneath `GITHUB_WORKSPACE`, matching the packet verification root.
In the unreleased v0.7.0 action, reports remain local to the runner by default.
Published v0.6.5 uploads reports by default, so the example states that choice
explicitly. For v0.7.0, set `upload-reports: "true"` only after approving GitHub
artifact retention; that opt-in uploads the packet, its privacy-filtered
assurance evidence graph, manifest, summaries, and CI diagnostics. Set
`upload-full-artifacts: "true"` only when the workflow is also approved to
retain compiled suites, fixture data, and RunSets. The default retention period
for either explicit upload is 14 days.

### Runtime coordination locks

Atomic publishers intentionally leave hidden coordination files beside their
output targets so another process cannot exploit lock unlink/replacement races.
If that parent directory is inside your repository, add this narrow rule to
**your repository's** `.gitignore` (the package cannot update it for you):

```gitignore
.agent-assure-*.lock
```

These lock files contain no assurance evidence or credentials and normally
remain on disk for reuse. Do not replace the rule with `*.lock`, which would
also hide dependency lockfiles and unrelated project state.

## Integrations and maturity

**Current published release: `v0.6.5` on GitHub and PyPI. This checkout is the
unreleased `0.7.0` candidate and must not be described or installed as a
published release until the empirical publish gate passes.**

The CLI, YAML authoring format, persisted versioned JSON artifacts, and
`AgentRunRecord` producer contract are the primary integration surface.
Framework adapters, streaming, and live execution remain experimental.
The RC label applies only to the primary surface; development-RFC contracts
remain non-stable. PyPI's `Development Status :: 4 - Beta` is the closest
standardized classifier to an RC and does not widen that surface.

| If you have… | Start with… | Maturity |
| --- | --- | --- |
| YAML suites or versioned JSON artifacts | [CLI contract](docs/cli_contract.md) | Primary supported surface |
| A GitHub release workflow | [Composite action](.github/actions/agent-assure/action.yml) | Packaged and documented |
| Deterministic mutation operators and closed catalog campaigns | [Core mutation catalog](docs/mutation_catalog.md) · [Evidence-carrying releases](docs/evidence_carrying_releases.md) | Development RFC |
| RAG retrieval evidence | [RAG provenance demo](docs/demo_rag.md) | Reference implementation |
| JSONL or multi-agent events | [Streaming example](examples/streaming_process_regression/README.md) | Experimental |
| LangGraph or Google ADK events | [LangGraph](docs/integrations/langgraph.md) · [Google ADK](docs/integrations/google_adk.md) | Experimental |
| Live provider or external-script subjects | [Adapter contract](docs/adapters/adapter_contract.md) | Experimental, time-bound evidence |
| Preregistered real-model measurement | [Real-model study](docs/real_model_study.md) | Untagged development contract; no study result published |
| Independently controlled CI learning pilot | [External pilot evidence](docs/external_pilot.md) | Untagged development contract; no qualifying pilot recorded |
| OpenTelemetry context or export | [OpenTelemetry alignment](docs/otel_alignment.md) | Optional alignment only |

Want to help with the still-unmet external evidence checkpoint? The
[short external pilot quickstart](docs/external_pilot_quickstart.md) targets
10–15 minutes of participant effort in a non-maintainer-controlled fork; CI
runtime may be longer. It needs no participant-supplied model key, proprietary
data, or repository secret. Interest or a workflow run is not evidence
completion: capture, participant friction/finalization and prospective consent,
and a byte-bound human review are all required for the pilot bundle.

<details>
<summary><strong>Experimental streaming semantics</strong></summary>

Here, idempotency refers only to idempotent deduplication for stable
at-least-once redeliveries. Conflicting duplicates fail closed; deterministic
sorting prevents out-of-order arrival jitter from changing the persisted
trajectory.

</details>

Framework adapters project only privacy-filtered `agent_assure` metadata into
the framework-neutral run-record model. They ignore raw prompts, messages,
completions, tool arguments, token chunks, and unredacted summaries.

## Governance crosswalks

Packet-resident evidence can be mapped to selected concepts in the
[NIST AI RMF](docs/governance_crosswalk_nist_ai_rmf.md),
[OWASP Top 10 for LLM Applications 2025](docs/governance_crosswalk_owasp_llm.md),
[ISO/IEC 42001](docs/governance_crosswalk_iso42001.md), and
[MITRE ATLAS 2026.06](docs/governance_crosswalk_mitre_atlas.md).

These crosswalks are planning and review aids. They do not establish framework
conformance, complete coverage, third-party assurance, or endorsement.

## Claim boundary

> **Measured evidence, not a blanket trust claim.**

This project is not a compliance attestation.

Generated artifacts make declared inputs, findings, limitations, and gate state
traceable and auditable for human review. Whether the release decision is
defensible remains a human and organizational judgment. `agent-assure` does not
determine safety or replace domain, legal, regulatory, clinical, security,
provider-quality, model-quality, or business-impact review.

| `agent-assure` is | `agent-assure` is not |
| --- | --- |
| Release-review evidence for declared process expectations | A legal or regulatory determination |
| A deterministic and protocol-bound measurement toolkit | A safety determination |
| A way to surface evidence, routing, privacy, boundary, provenance, usage, and stream-integrity regressions | A general model-quality benchmark |
| A local artifact and CI-gate workflow | A production observability backend or enterprise governance system of record |
| An engineering evidence source for human and governance review | A replacement for organizational accountability |

Pattern redaction is a guardrail, not comprehensive DLP or de-identification.
Live conclusions remain bounded by the declared protocol, data boundary,
provider/model configuration, and execution window. Review the
[claim boundary](docs/claim_boundary.md), [limitations](docs/limitations.md),
[threat model](docs/threat_model.md), [privacy model](docs/privacy_model.md),
and [security guidance](SECURITY.md).

## Learn more

- **Statistical methods:** [Repeated paired evidence sensitivity](docs/repeated_evidence_sensitivity.md) · [Preregistered real-model study](docs/real_model_study.md) · [Live calibration](docs/live_calibration.md)

- **Start:** [Documentation](docs/index.md) · [For AI leaders](docs/for_ai_leaders.md) · [For architects](docs/architecture.md) · [For engineers](docs/for_engineers.md)
- **Demos:** [Assure the assurance](docs/control_efficacy.md#one-command-demonstration) · [Flagship](docs/demo_flagship.md) · [RAG provenance](docs/demo_rag.md) · [Expense approval](docs/demo_expense.md)
- **Integrations:** [LangGraph](docs/integrations/langgraph.md) · [Google ADK](docs/integrations/google_adk.md) · [Adapter contract](docs/adapters/adapter_contract.md)
- **Assurance:** [What this measures](docs/what_this_measures.md) · [Control efficacy](docs/control_efficacy.md) · [Evidence packets](docs/evidence_packets.md) · [Live calibration](docs/live_calibration.md)
- **Evidence-carrying releases:** [Core mutation catalog](docs/mutation_catalog.md) · [Minimal evidence graph](docs/evidence_graph.md) · [Contracts and campaign guide](docs/evidence_carrying_releases.md) · [Architecture](docs/architecture.md) · [CLI contract](docs/cli_contract.md)
- **Security and governance:** [Claim boundary](docs/claim_boundary.md) · [Threat model](docs/threat_model.md) · [Security correction containment](docs/security_release_containment.md) · [Governance crosswalks](docs/threat_coverage_matrix.yaml)
- **Project:** [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [License](LICENSE)

<details>
<summary><strong>Development from a repository checkout</strong></summary>

```bash
pip install -e ".[dev]"
git config core.hooksPath .githooks
python scripts/check_docs_alignment.py
ruff check .
mypy src scripts
pytest
python -m build
```

</details>

## Citing

This project ships a [`CITATION.cff`](CITATION.cff). Use GitHub’s
**Cite this repository** control for generated citation formats.
