# Executive One Pager

`agent-assure` is a local, reproducible assurance and measurement substrate for
AI agent governance pipelines. It helps teams review whether a change preserved
expectations, evidence links, provider/tool controls, redaction boundaries,
escalation behavior, human-review routing, and declared live-protocol
assumptions without adopting a hosted governance platform.

## The Problem

Agentic systems are increasingly judged by the final answer they produce. That
is not enough for governance review. A pipeline can keep the same answer while
losing the evidence trail, bypassing an approved provider boundary, dropping a
human-review requirement, or leaking sensitive summary content.

Raw output hashes do not solve this. A hash can prove that material changed, but
it cannot decide whether the change violated an expectation.

Live agent behavior adds another measurement problem: repeated observations are
often correlated by case, source document, provider window, retry pattern, or
tool path. Treating every call as an independent pass/fail sample can overstate
confidence and hide operational burst behavior.

## The Method

`agent-assure` treats expectations as the primary oracle and protocols as the
boundary for live interpretation:

- compile labeled YAML suites into strict JSON artifacts;
- run baseline and candidate variants against identical local fixtures;
- evaluate the candidate against expectations and deterministic controls;
- compare baseline and candidate only after fixture equivalence passes;
- report provenance changes separately from verdict-bearing findings;
- run live observations only through declared adapters and frozen statistical
  protocols;
- preserve cluster structure, interval-center metadata, retry/exclusion status,
  provider/model provenance, cost, and latency;
- package summaries, environment metadata, digests, and interpretation guidance
  into reviewable evidence packets.

The included fixture examples are offline and deterministic. They do not
require a model-provider API key, live network calls, or token spend. Live mode
is explicit, protocol-bound, and opt-in.

## Flagship Result

The README demo compares a passing prior-authorization baseline with an
evidence-normalization candidate. Both use the same fixtures. For the affected
case, the visible answer remains:

```text
recommendation=approve
outcome=approve
```

The candidate still fails because the material `claim-duration` evidence link
is missing. The report identifies one blocking finding:

```text
case_id: shared-source-multi-claim
reason_code: MATERIAL_CLAIM_MISSING_EVIDENCE
classification: new_failure
fixture_equivalence_state: pass
```

This demonstrates the value of expectation-driven review: the visible answer
can be stable while a governance invariant regresses.

## What Ships Now

The repository includes:

- strict immutable schemas and deterministic JSON Schema export;
- lexeme-preserving YAML suite authoring and compilation;
- canonical RFC 8785 digest projection and HMAC-sensitive correlation tokens;
- privacy-filtered summaries, reports, packets, and span-plan previews;
- deterministic fixture runners for a synthetic prior-authorization suite and a
  neutral expense-approval suite;
- JSON, Markdown, and Rich reports for evaluation and comparison;
- CI gates with pass/fail/invalid-comparison exit behavior;
- evidence packets, dependency inventory, release manifests, digest replay, and
  keyless cosign workflow verification for exact signed blobs;
- OpenTelemetry-aligned span-plan preview from structured run records;
- explicit live-adapter commands for protocol-bound repeated observations,
  cluster-aware expectation-pass rates, provider/model group summaries,
  protocol-declared comparisons, and cost/latency distributions.
- optional advanced live endpoints for rare-event Poisson upper bounds,
  observed intraclass-correlation summaries, Bonferroni-controlled endpoint
  families, and paired exact or Monte Carlo randomization tests when design
  prerequisites are met;
- trajectory, drift, and operational event-process reports that surface
  observable state paths, history-dependent sequence checks, retry/rate-limit
  cascades, and burst-window reliability review signals;
- static JSONL, no-shell external-script, and OpenAI-compatible
  chat-completions adapters, with the OpenAI adapter implemented using Python
  standard-library HTTP support;
- optional OpenTelemetry SDK span emission and OTLP HTTP export from
  privacy-filtered span plans when `agent-assure[otel]` is installed.

## Boundaries

Live reports are time-bound to declared provider/model/configuration windows
and approved data boundaries. The project does not establish safety assurance,
prove regulatory compliance, validate clinical use, certify provider quality,
or claim OpenTelemetry adoption. Unsupported capabilities are surfaced as
`not_evaluated`.

Release signatures verify exact workflow identity and blob bytes. They are not
safety, compliance, clinical-validity, or standards-acceptance claims.

## Adoption Path

Start with a small fixture-mode suite around one governed workflow. Make the
expectations explicit, declare which claims are material, and run baseline and
candidate variants under shared fixtures. Use comparison reports for change
review, then publish evidence packets and release replay artifacts only after
the deterministic findings and limitations have been reviewed.
