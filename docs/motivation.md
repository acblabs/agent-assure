# Motivation

AI agent governance pipelines need repeatable checks for evidence linking,
policy enforcement, redaction, provider and tool gating, escalation, and review
logic. The final answer is only one part of the governed behavior. A pipeline
can keep the answer stable while losing the evidence trail or bypassing a
control that reviewers depend on.

That problem gets harder when agent behavior is stochastic, stateful, and
provider-mediated. The useful question is not whether an agent can be made
perfectly deterministic. It is whether the evaluation protocol, observable
state, statistical assumptions, and evidence artifacts are explicit enough for
reviewers to interpret a change without guessing.

`agent-assure` focuses on deterministic assurance first:

- fixed local fixtures rather than live provider calls;
- labeled expectations rather than baseline similarity;
- materiality declared by the fixture author rather than inferred from prose;
- provenance hashes treated as reproduction evidence rather than pass/fail
  shortcuts;
- reports and packets that reviewers can inspect without raw sensitive payloads.

This operationalizes Responsible AI controls in a narrow, reproducible form.
Teams can start by making expectations explicit for one governed workflow,
running baseline and candidate variants under shared fixtures, and using the
reports to decide whether a deterministic change should pass review.

The live path extends the same discipline to probabilistic provider behavior:
freeze a protocol, run repeated observations through declared adapters, preserve
cluster structure, analyze rates with declared guardrails, and keep trajectory,
drift, and event-process outputs as bounded review evidence. The project uses
statistical, state-space, dependence, and time-series diagnostics where they
match the data: clustered rates and intraclass correlation for repeated trials,
rare-event Poisson bounds for sparse failures, randomization tests for paired
designs, state-path summaries for observable execution trajectories, and
burst-window surveillance for retry or rate-limit cascades.

`agent-assure` is intentionally not another hosted governance platform. It is a
local package and CLI that writes review artifacts in the caller's workspace,
including reports, evidence packets, digests, release replay files, and
OpenTelemetry-aligned span plans when requested.

The project intentionally avoids employer-specific implementation details and
domain-confidential logic. The included examples are synthetic demonstrations:
one prior-authorization-style suite for a realistic evidence-linking edge case
and one neutral expense-approval suite to show that the method is not tied to a
single domain.
