# Claim Boundary

`agent-assure` produces measured, local-first evidence for human review. It can
produce evidence packets, deterministic fixture findings, CI-gate signals,
artifact digests, traceability summaries, static evidence-diff artifacts, and
single-operator assurance mutation results.

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

Avoid wording that turns a local review artifact into a broad outcome claim.
Do not describe these releases as carrying proofs. Reserve proof terminology
for an actual cryptographic inclusion proof or a formal result within its
explicitly declared abstraction. A caught mutation means the normative
expected detector responded to that exact transformation; it does not
establish broader system correctness.
