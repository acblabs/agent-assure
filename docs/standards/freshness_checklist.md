# Standards Freshness Checklist

Freshness status: complete for the current v0.1 documentation set.

Last manual review: 2026-06-27.

## Reviewed Artifacts

| Artifact | Status |
| --- | --- |
| `compat/otel_genai_semconv.lock` | Present; records local snapshot `otel-semconv-genai-snapshot-local` and checksum `5d57cc08de8fb8f34b648cd8d7c0a5f6ad1a9bdb0faef558f18d0baf59f56a52`. |
| `compat/otel_mapping_matrix.yaml` | Present; lists emitted and deliberately not emitted attributes. |
| `docs/otel_alignment.md` | Present; documents local mapping boundaries. |
| `docs/standards/otel_genai_gap_analysis.md` | Present; records the current gap assessment and reviewed sources. |
| `docs/standards/otel_contribution_candidate.md` | Present; defers upstream contribution until SDK/export evidence exists. |
| OpenTelemetry GenAI docs | Reviewed at https://opentelemetry.io/docs/specs/semconv/gen-ai/. |
| OpenTelemetry semantic-conventions-genai repository | Reviewed at https://github.com/open-telemetry/semantic-conventions-genai. |

## Gate Criteria

Before opening an upstream issue or making a stronger interoperability claim:

- review the current OpenTelemetry GenAI semantic-convention documentation;
- review the current semantic-conventions-genai repository and open issue or
  discussion inventory;
- compare existing attributes against `compat/otel_mapping_matrix.yaml`;
- confirm whether the candidate gap remains real;
- update this checklist with the review date, external source references, and
  local lock/checksum status;
- keep contribution language narrow and evidence-backed;
- keep v0.1 public wording at "OpenTelemetry-aligned" unless a future upstream
  process creates a stronger basis.

## Current Decision

The current decision is to defer upstream contribution. The local preview maps
structured fields to the pinned compatibility matrix and uses project-local
`agent_assure.*` attributes for local provenance. That is sufficient for v0.1.

The next review should happen before any v0.2 SDK/export implementation is
presented as interoperable telemetry or before any public upstream discussion is
opened.
