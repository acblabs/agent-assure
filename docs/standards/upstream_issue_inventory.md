# Upstream Issue Inventory

No upstream OpenTelemetry issue is ready to open for the current implementation.

Current inventory status:

| Candidate | Status | Rationale |
| --- | --- | --- |
| Offline deterministic evaluation artifacts associated with GenAI agent runs | Deferred | The project produces span-plan previews and optional SDK/OTLP exports, but current project-local attributes are sufficient and no upstream gap has been confirmed. |
| Fixture-equivalence result as a telemetry concept | Deferred | This is meaningful for `agent-assure` comparison reports, but it has not been demonstrated as a vendor-neutral telemetry need. |
| Evidence packet digest or release replay digest attributes | Deferred | Digests are release/reproducibility artifacts. They should not become generic telemetry attributes without exported span evidence and upstream maintainer interest. |

Before updating this inventory, repeat the freshness review in
`docs/standards/freshness_checklist.md` and confirm that current OpenTelemetry
GenAI documentation and discussions do not already answer the question.
