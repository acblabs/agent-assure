# agent-assure

`agent-assure` is a local-first assurance and measurement toolkit for AI agent
governance pipelines. It treats agentic governance as a measurement problem:
declare expectations, bind fixtures or live protocols, run candidate pipelines,
and produce reviewable evidence about observable behavior instead of relying on
final-answer comparison or a hosted governance platform.

The project is designed for reviewers who need to know whether a candidate
pipeline preserved explicit expectations, material evidence links,
provider/tool boundaries, redaction behavior, escalation logic, human-review
routing, live-protocol assumptions, and provenance under reproducible local
commands.

The core premise is simple: **output equivalence is not process equivalence**.
If an agentic AI process changes and still returns the same recommendation,
approval, denial, or summary, the surrounding pipeline may still have changed
in material ways. Evidence links may be missing, a different provider or tool
may have been used, redaction behavior may have shifted, review routing may
have been bypassed, retries may have cascaded, or provenance may no longer
match the reviewed configuration. `agent-assure` measures those observable
pipeline behaviors around the result so reviewers can distinguish stable
answers from preserved governance controls.

The result is evidence designed to support reproducibility, traceability,
auditability, observability, and review defensibility. Those properties come
from local commands, strict schemas, explicit expectations, protocol records,
canonical digests, privacy-filtered reports, evidence packets, CI gates,
release replay, and OpenTelemetry-aligned span plans. They are review supports,
not safety, compliance, clinical-validity, or standards-acceptance claims.

## Why this is different

- **Evidence before dashboards.** `agent-assure` runs as a local package and
  writes review artifacts in your workspace instead of requiring a hosted
  governance platform.
- **Offline fixture assurance.** The included fixture demos and CI gates run
  without a provider API key, network call, or token spend.
- **Statistical controls for probabilistic systems.** Live reports preserve
  clustering, report pooled and cluster-mean rates, expose design-effect and
  effective-sample metadata, support Bonferroni-controlled endpoint families,
  rare-event Poisson upper bounds, observed intraclass-correlation summaries,
  and paired exact or Monte Carlo randomization tests when prerequisites are
  declared and met.
- **Observable trajectory analysis.** Live trajectory reports derive
  privacy-filtered state paths, transition profiles, history-dependent
  sequence checks, and operational event-process summaries for retries,
  rate-limit storms, malformed outputs, runtime failures, emergency process
  records, and budget stops. These are review signals over structured
  artifacts, not claims about hidden model state.
- **Thin live adapters and observability alignment.** Live execution includes a
  static JSONL adapter, a no-shell external-script adapter, and an
  OpenAI-compatible chat-completions adapter implemented with Python's standard
  library HTTP client. Runtime W3C `traceparent` context is propagated into
  live adapters and can be projected into OpenTelemetry-aligned span plans with
  optional SDK/OTLP export.

The implemented surface spans suite authoring and compilation, deterministic
fixture runs, canonical digests, expectation evaluation, privacy-filtered
reports, evidence packets, CI gates, release replay, protocol-bound live
analyses, and OpenTelemetry-aligned span plans.

Live reports are time-bound operational evidence for declared
provider/model/configuration windows; they do not establish safety assurance,
validate clinical use, prove regulatory compliance, provide general
provider-quality evidence, or claim OpenTelemetry adoption. Release evidence
can be signed and verified for exact workflow identity; that signature is not a
safety, compliance, or clinical-validity claim.

## Install

`agent-assure` is not currently published on PyPI. Install it from a local
repository checkout instead.

For normal local CLI use:

```bash
pip install -e .
```

For the flagship demo and local validation checks, install the development
extras:

```bash
pip install -e ".[dev]"
```

## Five-minute flagship demo

Run these commands one at a time from the repository root. The final two
commands write reports and are expected to exit `1`; the GitHub Actions snippet
below shows how to assert those expected failures in `set -e` contexts.

```bash
pip install -e ".[dev]"
mkdir -p .tmp/showcase
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/showcase/prior-auth.compiled.json --manifest .tmp/showcase/prior-auth.fixtures.json
agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.baseline.json
agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.evidence-candidate.json
agent-assure evaluate .tmp/showcase/prior-auth.baseline.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/baseline-report
agent-assure evaluate .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/evidence-report
agent-assure compare .tmp/showcase/prior-auth.baseline.json .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/comparison-report
agent-assure ci .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --baseline .tmp/showcase/prior-auth.baseline.json --out-dir .tmp/showcase/ci-report --report-mode full
```

The baseline evaluation exits `0` and writes a `pass` summary with ten evaluated
cases and zero blocking findings. The candidate evaluation is expected to exit
`1`; its report contains one blocking finding for
`shared-source-multi-claim` with reason code
`MATERIAL_CLAIM_MISSING_EVIDENCE`.

The comparison command is also expected to exit `1`. It writes
`.tmp/showcase/comparison-report/comparison-report.md` with classification
`new_failure` and fixture-equivalence state `pass`. For the failing case, the
baseline and candidate both keep `recommendation=approve; outcome=approve`; the
material regression is the missing `claim-duration` evidence link. See
`docs/showcase.md` for the expected report fields, GitHub Actions snippet, and
artifact digest summary.

After reports exist, an evidence packet can also be built and gated from
summaries:

```bash
agent-assure packet build .tmp/showcase/evidence-report/evaluation-summary.json --comparison .tmp/showcase/comparison-report/comparison-summary.json --out .tmp/showcase/evidence-packet.json
agent-assure ci gate .tmp/showcase/evidence-packet.json
```

For this known failing candidate, both the CI command and packet gate are
expected to exit `1`. The CI command writes JSON/Markdown reports,
`evidence-packet.json`, `evidence-packet.md`, `dependency-inventory.json`,
`release-artifact-manifest.json`, and `ci-diagnostics.json`.

Release evidence can be bundled and replayed from raw digests for stable source
artifacts and stable JSON projection digests for environment-bearing packet
artifacts:

```bash
python scripts/build_release_bundle.py --out .tmp/release --write-digests .tmp/release/release-digest-replay.json
agent-assure release replay .tmp/release/release-digest-replay.json --artifact-root . --require-current-commit
```

The release bundle includes the evidence packet, release manifest, replay file,
SBOM, source distribution, wheel, manifest-listed digest cross-checks, and
exact cosign-verifiable blobs when built by the release workflow. For keyless
cosign verification of workflow-signed release blobs, see
`docs/release_evidence.md`.

## What the demo shows

The flagship demo is intentionally narrow. It shows that a candidate can keep
the same visible answer while losing a material evidence link, and that the
evaluation report identifies the failing invariant under equivalent fixtures.
It does not show live model quality, safety, compliance, clinical validity, or
standards acceptance.

### Flagship regression at a glance

The key idea: ordinary output comparison can miss governance regressions. In the
flagship fixture, the candidate keeps the same visible recommendation and
outcome as the baseline, but drops a material evidence link. `agent-assure`
catches the missing evidence invariant and classifies the baseline-to-candidate
comparison as a `new_failure` under passing fixture equivalence.

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

    classDef pass fill:#e5f5ff,stroke:#0072b2,color:#003b5c;
    classDef fail fill:#fff1e0,stroke:#d55e00,color:#5c2a00;
    classDef neutral fill:#eef3ff,stroke:#3f51b5,color:#1a237e;
    classDef warn fill:#fff8e1,stroke:#f9a825,color:#5d4037;

    class Pass,Equiv pass;
    class Fail,NewFailure fail;
    class Same,Compare neutral;
    class Tension warn;
```

## Architecture

This is the full toolkit shape. The five-minute demo exercises the fixture-mode
path and evidence outputs.

```mermaid
flowchart LR
  A[Authoring<br/>YAML suites<br/>live protocols] --> B[Compile and bind<br/>strict JSON<br/>canonical digests]
  B --> C{Execution}
  C -->|Fixture mode| D[Fixed local fixtures<br/>offline<br/>no token spend]
  C -->|Live mode| E[Declared adapters<br/>static JSONL<br/>external script<br/>OpenAI-compatible]
  D --> F[RunSet records<br/>redacted summaries<br/>provenance<br/>trace context]
  E --> F
  F --> G[Evaluate controls<br/>expectations<br/>policies<br/>privacy checks]
  G --> H[Change review<br/>fixture equivalence<br/>verdicts<br/>provenance diffs]
  G --> I[Live review<br/>cluster rates<br/>rare-event bounds<br/>drift and trajectories]
  H --> J[Evidence outputs<br/>reports<br/>packets<br/>CI gates<br/>release replay]
  I --> J
  J --> K[Observability<br/>span plans<br/>optional SDK/OTLP]
```

## Small generic example

The expense-approval example is a compact non-healthcare suite that uses the
same offline fixture and expectation method. It is a generic demonstration, not
a benchmark.

```bash
agent-assure suite compile examples/expense_approval_minimal/suite.yaml --out .tmp/expense.compiled.json --manifest .tmp/expense.fixtures.json
agent-assure suite run .tmp/expense.compiled.json --variant examples/expense_approval_minimal/variants/baseline.yaml --manifest .tmp/expense.fixtures.json --out .tmp/expense.baseline.json
agent-assure suite run .tmp/expense.compiled.json --variant examples/expense_approval_minimal/variants/candidate_provider_policy.yaml --manifest .tmp/expense.fixtures.json --out .tmp/expense.candidate.json
agent-assure evaluate .tmp/expense.baseline.json --suite .tmp/expense.compiled.json --out-dir .tmp/expense.baseline-report
agent-assure evaluate .tmp/expense.candidate.json --suite .tmp/expense.compiled.json --out-dir .tmp/expense.candidate-report
```

The baseline evaluation exits `0`. The provider-policy candidate is expected to
exit `1` with deterministic provider, outcome, and human-review control
findings.

## Current claim boundary

The project currently claims deterministic offline controls and
protocol-bound live operational evaluation implemented in this repository.
Public claims are tracked in
`docs/claims_traceability_matrix.yaml`.

A statistical protocol is documented in
`docs/measurement/experiment_protocol.md` for live stochastic evaluation. The
`agent-assure live` commands require a machine-readable protocol, run
explicitly configured adapters, and analyze repeated observations with
cluster-aware rates, protocol-declared comparison methods, and exploratory
guardrails for low cluster counts. Optional advanced endpoint plans bind
confirmatory/exploratory labels, Bonferroni multiplicity controls, rare-event upper
bounds, observed cluster-correlation summaries, and paired randomization-test
prerequisites to the protocol digest. Optional trajectory reports derive
privacy-filtered observable state paths, canonical transition profiles,
sequence invariants, and operational event-process summaries from structured
run artifacts. Live results remain bounded by the declared
protocol, data boundary, provider/model configuration, and execution window.
They are not general model-quality, safety, compliance, or clinical-validation
claims.

Synthetic calibration and regression coverage for the live statistical,
drift-monitoring, trajectory, and event-process paths is summarized in
`docs/live_calibration.md`.

The `external-script` live adapter runs configured scripts through a no-shell
subprocess harness and records redacted `emergency-process-record` artifacts
for process failures. It passes only declared environment allowlist entries,
explicit config variables, and runner-injected trace/request variables.
OpenTelemetry export is optional:

```bash
pip install -e ".[otel]"
agent-assure otel export RUNSET_OR_RECORD_OR_SPAN_PLAN.json --protocol otlp-http --endpoint http://localhost:4318/v1/traces
```

Exported spans are derived from span plans and structured run records, not live
SDK instrumentation of provider calls; raw prompts, raw outputs, tool
arguments, and unredacted summaries are not emitted.

## GitHub Actions snippet

```yaml
name: agent-assure-showcase
on: [push, pull_request]
jobs:
  flagship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev]"
      - run: mkdir -p .tmp/showcase
      - run: agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/showcase/prior-auth.compiled.json --manifest .tmp/showcase/prior-auth.fixtures.json
      - run: agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.baseline.json
      - run: agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.evidence-candidate.json
      - run: agent-assure evaluate .tmp/showcase/prior-auth.baseline.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/baseline-report
      - name: Evaluate evidence candidate
        run: |
          set +e
          agent-assure evaluate .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/evidence-report
          status=$?
          set -e
          if [ "$status" -ne 1 ]; then
            echo "expected exit 1, got $status"
            exit 1
          fi
          grep -q "MATERIAL_CLAIM_MISSING_EVIDENCE" .tmp/showcase/evidence-report/evaluation-report.md
      - name: Compare baseline to candidate
        run: |
          set +e
          agent-assure compare .tmp/showcase/prior-auth.baseline.json .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/comparison-report
          status=$?
          set -e
          if [ "$status" -ne 1 ]; then
            echo "expected exit 1, got $status"
            exit 1
          fi
          grep -q 'Classification: `new_failure`' .tmp/showcase/comparison-report/comparison-report.md
          grep -q 'Fixture-Equivalence Result' .tmp/showcase/comparison-report/comparison-report.md
          grep -q 'State: `pass`' .tmp/showcase/comparison-report/comparison-report.md
```

## Development

```bash
git config core.hooksPath .githooks
python scripts/check_docs_alignment.py
ruff check .
mypy src
pytest
python -m build
```

Dependency locking for release builds is documented in
`docs/dependency_locking.md`. Release bundle reproduction, SBOM generation, and
cosign verification are documented in `docs/release_evidence.md`.

The installed package includes bundled deterministic examples for reproducible
local demos. They are not a stable extension API; see `docs/api_surface.md`.
