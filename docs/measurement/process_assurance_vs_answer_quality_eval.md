# Process Assurance vs Answer-Quality Evals

Answer-quality evals measure answer quality. `agent-assure` measures preservation
of structured process evidence under a declared field origin. These are
complementary axes, not a ranking of tools or a claim that one measurement
replaces the other.

An answer-quality eval is the right instrument when the question is whether a
model or agent produced a better, worse, or acceptable answer. A process
assurance check is the right instrument when the visible answer may stay stable
while the governed path around that answer changes: evidence links, provider
boundaries, review routing, redaction behavior, retries, or measured usage.

`agent-assure` is deliberately scoped to local, deterministic review artifacts.
It does not certify safety, compliance, clinical validity, or live model
quality. It gives reviewers structured evidence about whether a candidate run
preserved the process expectations declared for a suite.

| Failure mode | Output-only eval | agent-assure |
| --- | --- | --- |
| Same answer, missing evidence link | Often invisible | Detected when the declared source supplies eligible evidence fields |
| Same answer, provider boundary changed | Often invisible | Detected in the source-qualified run record |
| Same answer, human review bypassed | Often invisible | Detected only from eligible review-route evidence, not model self-report |
| Same answer, evidence source identity changed | Often invisible | Detected in the source-qualified evidence graph |
| Same answer, retry/cost regression | Invisible | Detected when runner-observed usage is present |
| Different answer quality | Visible | Contextual/secondary |

The bundled process-measurement fixture suite uses evidence-source identity
drift instead of a redaction-state case; redaction behavior remains observable
when a suite declares and captures that field.

The distinction matters during release review. A candidate can keep the same
recommendation and outcome while dropping the evidence link that made the
decision auditable. Another candidate can keep the answer stable while changing
from an approved provider boundary to a different provider, changing evidence
source identity, bypassing a declared human-review route, or increasing retries
and declared estimated cost.

Those examples are not competitive benchmark claims. They are deterministic
fixtures that clarify what the project measures: declared process evidence
around an agent decision. An instrumented adapter can supply producer-attested
runtime fields, but direct model self-report cannot establish that a tool,
evidence access, policy evaluation, or human review occurred. Teams should
continue using answer-quality evals, domain validation, safety review, and live
monitoring for the questions those methods are designed to answer.
