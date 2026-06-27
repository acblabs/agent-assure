# OTel Contribution Candidate

Candidate status: deferred.

No upstream issue or specification change is proposed for the current v0.1
implementation. `agent-assure` produces an OpenTelemetry-aligned span-plan
preview, not OpenTelemetry SDK spans or OTLP exports. The preview is useful
implementation evidence for local review, but it is not enough to justify new
vendor-neutral attributes.

## Narrow Candidate

If future SDK/export work shows that a gap remains, the narrowest upstream
candidate is a discussion issue with this question:

```text
Do the current GenAI semantic conventions intend to cover offline deterministic
evaluation and release-evidence artifacts associated with agent runs, such as
fixture-equivalence results, evaluation summaries, and evidence packet digests?
```

The preferred initial outcome is clarification, examples, or documentation
guidance. A new attribute proposal should be considered only if maintainers
confirm that the use case is in scope, existing attributes do not cover it, and
real exported span data demonstrates the gap.

## Evidence Required Before Opening

Before any upstream discussion, the project should have:

- actual OpenTelemetry SDK spans, not only span-plan previews;
- runtime context propagation for the evaluated workflow;
- examples showing how evaluation artifacts relate to agent, model, and tool
  spans without including raw prompts, outputs, tool arguments, or sensitive
  identifiers;
- a reviewed mapping from structured `agent-assure` fields to existing GenAI
  attributes;
- confirmation that the current upstream documentation and issue inventory do
  not already address the question.

## Non-Goals

The candidate must not:

- claim OpenTelemetry adoption or acceptance;
- request project-specific `agent_assure.*` attributes as generic attributes;
- propose token, cost, or latency metrics before live runs measure them;
- encode safety, compliance, clinical-validity, or regulatory conclusions in
  telemetry attributes;
- expose raw fixture payloads, prompts, outputs, tool arguments, or sensitive
  identifiers.

## Draft Discussion Shape

The future discussion should be short and evidence-backed:

1. Describe the deterministic offline evaluation use case.
2. Link to reproducible artifacts and span examples from the SDK/export work.
3. Show the existing attribute mapping first.
4. Ask whether examples or guidance are sufficient.
5. Propose no new attribute unless the gap is confirmed.

Until that evidence exists, the repository should continue to document the
preview as OpenTelemetry-aligned and keep all project-local provenance under the
`agent_assure.*` namespace.
