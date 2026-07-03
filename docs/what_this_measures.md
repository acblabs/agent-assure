# What This Measures

Output-only evals compare the final answer. `agent-assure` evaluates declared,
observable process expectations around the answer: evidence links,
provider/tool boundaries, redaction behavior, escalation logic, review routing,
provenance, fixture equivalence, and CI-gate behavior.

These are complementary axes. An answer-quality eval may say whether the final
response is good. `agent-assure` asks whether the governed process that produced
the response preserved the controls reviewers expected.

Example: the flagship fixture keeps `recommendation=approve; outcome=approve`,
but the candidate drops a material evidence link. Output equivalence is
preserved in the decision the reviewer sees; process equivalence is not.
