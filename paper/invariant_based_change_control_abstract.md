# Abstract

AI agent governance pipelines can regress in ways that are not visible through
raw answer comparison alone. This report presents invariant-based change control
for deterministic governance-pipeline evaluation: hold requests, model outputs,
tool outputs, and fixture manifests fixed; resolve labeled expectations; check
candidate behavior against explicit invariants and policies; and report
provenance changes separately from verdict-bearing findings. The accompanying
implementation provides strict persisted schemas, runtime and JSON Schema
parity, lexeme-preserving YAML authoring, RFC 8785 digest projection,
HMAC-sensitive correlation tokens, privacy-filtered summaries, deterministic
fixture runners, evaluation and comparison reports, evidence packets, CI gates,
release digest replay, and an OpenTelemetry-aligned span-plan preview. In the
flagship fixture suite, an evidence-normalization candidate preserves the
visible recommendation and outcome for a shared-source case while losing the
material `claim-duration` evidence link; the invariant failure is reproducible
under equivalent fixtures and classified as a new failure. The approach is
deliberately scoped to offline fixture-mode assurance. The broader repository
also includes a separately scoped, protocol-bound live evaluation path, but
those live statistical, drift, trajectory, and event-process reports are
outside this paper's empirical contribution. This report does not estimate live
model-quality rates, establish safety assurance, prove regulatory compliance,
validate clinical use, or claim standards adoption.
