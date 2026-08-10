# Claim Boundary

`agent-assure` produces measured, local-first evidence for human review. It can
produce evidence packets, deterministic fixture findings, CI-gate signals,
artifact digests, traceability summaries, static evidence-diff artifacts, and
assurance-mutation campaigns, control-efficacy reports, and single-operator
mutation results.

The product role is Agent Release Assurance Compiler. An Evidence-Carrying
Agent Release carries versioned, inspectable evidence about declared controls;
the name does not imply that every relevant property was evaluated.

This project is not a compliance attestation. Safety review remains a separate
human and organizational responsibility.

The project does not replace legal, regulatory, clinical, provider-quality,
model-quality, or business-impact review. It reports observed process facts:
which expectations were evaluated, which findings were observed, which
artifacts were produced, and which gate state followed from the configured
rules.

Preferred release-facing language:

- measured evidence;
- review support;
- traceability;
- control coverage;
- measured usage delta;
- declared estimated cost evidence;
- observed process regression;
- local evidence packet;
- CI-gate signal;
- evidence-carrying agent release;
- expected control detection;
- operator provenance and independence class.
- exact catalog detector kill ratio with its numerator and denominator;
- required or critical mutation survivor;
- independent challenge eligibility; and
- control-efficacy semantic state and configured gate decision.

Avoid wording that turns a local review artifact into a broad outcome claim.
Do not describe these releases as carrying proofs. Reserve proof terminology
for an actual cryptographic inclusion proof or a formal result within its
explicitly declared abstraction. A caught mutation means the normative
expected detector responded to that exact transformation; it does not
establish broader system correctness.

A catalog detector kill ratio must remain attached to its exact campaign,
catalog, source, suite, evaluator, manifest, selected operators, outcome counts,
and independence strata. Do not restate it as a numeric claim about system
safety, security, robustness, or reliability. A confidence interval belongs to
a separately declared statistical protocol; the deterministic catalog ratio is
not one.

Keep semantic evidence and policy language distinct. `survivor_observed` is a
fact derived from campaign outcomes. `fail`, `warn`, or `pass` is the result of
mapping those facts through a gate profile. Changing an effect must not be
described as changing which mutation was caught or survived.
