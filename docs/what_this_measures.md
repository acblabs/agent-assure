# What This Measures

Output-only evals compare the final answer. `agent-assure` evaluates declared,
structured process-evidence expectations around the answer: evidence links,
provider/tool boundaries, redaction behavior, escalation logic, review routing,
provenance, fixture equivalence, and CI-gate behavior.

These are complementary axes. An answer-quality eval may say whether the final
response is good. `agent-assure` asks whether the source-qualified record
preserved the controls reviewers expected. It does not infer that an external
process event occurred merely because a model or another producer supplied a
corresponding field.

Example: the flagship fixture keeps `recommendation=approve; outcome=approve`,
but the candidate drops a material evidence link. Output equivalence is
preserved in the authored decision, while the declared fixture evidence is not.
