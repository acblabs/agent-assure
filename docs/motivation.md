# Motivation

AI agent governance pipelines need repeatable checks for evidence linking,
policy enforcement, redaction, provider and tool gating, escalation, and review
logic. The final answer is only one part of the governed behavior. A pipeline
can keep the answer stable while losing the evidence trail or bypassing a
control that reviewers depend on.

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

The project intentionally avoids employer-specific implementation details and
domain-confidential logic. The included examples are synthetic demonstrations:
one prior-authorization-style suite for a realistic evidence-linking edge case
and one neutral expense-approval suite to show that the method is not tied to a
single domain.
