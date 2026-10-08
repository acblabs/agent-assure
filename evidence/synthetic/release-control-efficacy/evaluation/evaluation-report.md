# Evaluation Report

## Candidate vs Expectations

- State: `pass`
- Run set: `runset-69e59deb-4cf5-500e-bb17-405262e32611`
- Suite: `prior-auth-synthetic` version `0.1.0`
- Gate profile: `default`

## Why the Candidate Passed or Failed

The candidate satisfies the compiled expectations and deterministic controls evaluated for this fixture suite.

## Failed Controls

No blocking controls failed.

## Warning Controls

No warning controls were emitted.

## Waiver Dispositions

No waivers were supplied.

## Not-Evaluated Capabilities

- `raw_payload_persistence_forbidden`: `not_evaluated` - runset writers redact summary fields and evaluation checks raw summaries, but no evaluator policy inspects external raw payload storage
- `live_stochastic_model_quality_regression`: `not_evaluated` - fixture mode does not run live stochastic model comparisons
- `production_runtime_isolation`: `not_evaluated` - offline run records do not observe production sandbox isolation
- `regulatory_compliance_certification`: `not_evaluated` - deterministic checks do not certify legal or regulatory compliance

## Metrics

- Total cases: `10`
- Evaluated cases: `10`
- Unevaluated cases: `0`
- Passed cases: `10`
- Warning cases: `0`
- Failed cases: `0`
- Blocking findings: `0`
- Global blocking findings: `0`
- Warning findings: `0`

Warn-only, waived, and gate-profile-filtered fail findings count as warning cases rather than clean passes or failed cases. Passed, warning, failed, and unevaluated cases partition total cases. Global gate failures are reported separately from case outcome counts.

## Measured Usage

- measured usage: `not_observed`

## Limitations

- offline fixture evaluation does not certify safety, compliance, clinical validity, or live model quality
