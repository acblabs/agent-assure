# Adapter Contract

Status: experimental framework adapter contract.

Framework adapters translate framework observations into existing
agent-assure artifacts. Evaluation remains framework-neutral: once an adapter
has produced `AgentRunRecord`, usage, evidence, and provenance fields, the
ordinary expectation and invariant evaluator decides pass or fail.

## Observation Shape

The core observation model is `FrameworkObservation` in
`agent_assure.adapters.base`. It records only allowlisted process metadata:

- framework name and optional framework version;
- run, case, sequence, timestamp, node, and event identifiers;
- provider, model, tool name, human-review route, evidence references, and
  redaction state;
- optional `UsageSegment`;
- optional span context and privacy-filtered attributes.

The model does not include raw prompts, raw completions, raw tool arguments,
message arrays, raw input/output payloads, or unredacted summaries. Adapter
metadata using those raw key names is rejected. Privacy-filtered attribute,
span-context, and adapter-controlled top-level label values such as
`provider`, `model`, `tool_name`, and `review_route` must be compact tokens,
labels, or digests rather than free-text summaries. Usage segment string
fields that adapters control, such as `operation` and `cost_basis`, follow the
same compact-token rule. This is a producer contract and validation heuristic,
not semantic raw-text detection. Prefer canonical tokens such as
`azure-openai`, `gpt-4-turbo`, `manager_review`, or `sha256:0123...` over
display labels with spaces or raw payload fragments.

The helper that projects framework observations into `AgentRunRecord` emits
fixture-mode review artifacts. It is for deterministic offline or declared
observation records. Final `recommendation` and `outcome` values must be
observed in privacy-filtered observation attributes; the projection helper does
not treat static projection values as measured framework output by default.
When producers emit `human_review_required` or `human_review_performed`,
values must be the compact strings `"true"` or `"false"`; malformed present
values fail closed rather than falling back to projection defaults. Observed
review flags override the projection helper's static defaults. When a
projection declares `human_review_required=True`, the projection helper fails
closed unless both review flags were observed; callers can pass
`require_observed_human_review=False` only for explicitly declarative fixture
records. Route labels such as `review_route` remain observable evidence, but
built-in deterministic evaluation gates the required human-review and
performed-review flags rather than route-string equality unless a downstream
policy adds that invariant.
Protocol-bound live mode remains the responsibility of the live runner because
live records require repetition, schedule, cluster, budget, and protocol
metadata.

## Producer Duties

An adapter should:

- preserve deterministic ordering with `sequence_number`; parallel or fan-out
  nodes in the same framework update must each emit distinct sequence numbers;
- reject duplicate `sequence_number` or `observation_id` values for a run;
- create stable observation IDs from framework, run, node, event, and sequence
  fields when the framework does not supply one;
- attach measured usage as `UsageSegment` values when usage is observed;
- keep usage labels compact and scrubbed rather than storing prompt or
  completion text in usage metadata;
- map evidence references to explicit `claim_evidence_links` and
  content-digested `evidence_items` before producing an `AgentRunRecord`;
- emit the observed final `recommendation` and `outcome` as compact
  privacy-filtered attributes on a decision observation;
- emit observed `human_review_required` and `human_review_performed` compact
  boolean attributes when human-review routing is part of the measured process;
- keep provider, tool, and review-route boundaries observable;
- treat raw framework payloads as input to the application, not as persisted
  assurance evidence.

The adapter API is not a stable plugin API yet. LangGraph, Google ADK, and
future framework integrations should target the same observation contract
rather than adding framework-specific evaluation paths.
