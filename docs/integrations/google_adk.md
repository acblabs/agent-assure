# Google ADK Integration

Status: experimental.

Install the optional dependency when running against real Google ADK code:

```bash
pip install "agent-assure[adk]"
```

The optional extra targets the Google ADK 2.x event and workflow line with
`google-adk>=2.4,<3`. PyPI release metadata records `google-adk` 2.4.0 files
uploaded on July 7, 2026; that release is the compatibility floor for this
experimental adapter. The adapter itself can be imported without Google ADK
installed so tests and fixture examples stay offline.

## How It Works

`GoogleADKAdapter` reads `agent_assure` metadata from ADK-style event mappings
or event objects. For real ADK `Event` objects, prefer `custom_metadata` for
event labels and `actions.state_delta` for state-update events. The adapter
also accepts explicit fixture mappings under `metadata`, `state_delta`, or
nested workflow-node updates. It ignores raw event content, message parts,
function-call arguments, completions, and unredacted summaries.

The `[adk]` extra installs Google ADK only. It does not instrument an ADK app
or provide a first-class runner/session helper. Assurance still requires the
application to emit privacy-filtered `agent_assure` metadata into events that
are passed to `GoogleADKAdapter.observations_from_events`.

Application code should emit only privacy-filtered metadata, using compact
labels or digests for `privacy_filtered_attributes`, top-level labels such as
`provider`, `model`, `tool_name`, and `review_route`, and usage labels such as
`operation` and `cost_basis`. Use canonical tokens such as `google-vertex-ai`,
`gemini-2.5-flash`, or `clinical_review` rather than display labels with
spaces.

```python
{
    "custom_metadata": {
        "agent_assure": {
            "case_id": "adk-benefit-001",
            "event_type": "delegation",
            "sequence_number": 2,
            "node_name": "policy_agent",
            "tool_name": "benefit_policy_lookup",
            "evidence_refs": ["ref-benefit-policy-v9"],
            "redaction_state": "redacted",
            "privacy_filtered_attributes": {
                "delegation_route": "root_to_policy_agent",
                "policy_version": "benefit-policy-v9",
            },
        }
    }
}
```

For state updates, the adapter also reads the ADK action state delta:

```python
{
    "actions": {
        "state_delta": {
            "agent_assure": {
                "case_id": "adk-benefit-001",
                "event_type": "review_route",
                "sequence_number": 3,
                "node_name": "review_agent",
                "review_route": "clinical_review",
                "redaction_state": "redacted",
                "privacy_filtered_attributes": {
                    "human_review_required": "true",
                    "human_review_performed": "true",
                },
            }
        }
    }
}
```

Decision observations must emit the observed final `recommendation` and
`outcome` in `privacy_filtered_attributes`. Review-route observations can emit
compact `human_review_required` and `human_review_performed` values of
`"true"` or `"false"`; the shared projection helper prefers those observed
flags over static projection defaults and rejects any other present value. When
human-review routing is part of the measured process, call the projection
helper with `require_observed_human_review=True` so absent review flags fail
closed instead of falling back to projection defaults. Without that option,
projection review booleans are fallback declarations, not trajectory evidence.
From there, the normal agent-assure evaluator checks expected outcomes,
required evidence, material claim links, provider/tool boundaries, the required
human-review flag, and redaction controls. The `review_route` token remains
observable evidence, but the built-in deterministic review control does not
perform route-string equality unless a downstream policy adds that check. There
is no ADK-specific evaluator.

The current projection helper emits fixture-mode review artifacts only. Do not
use it to label stochastic production traffic as live evidence; protocol-bound
live runs must go through the live runner.

## Offline Example

The repository includes `examples/adk_process_assurance`. The baseline keeps
the final decision, policy evidence, delegation route, human-review route, and
provider/tool boundary. The candidate keeps the same final decision and
evidence but switches to an automatic path and reports
`human_review_required="false"`, so the ordinary human-review and
provider-boundary controls fail.

```bash
python examples/adk_process_assurance/run_example.py
```

The example runs offline from a synthetic ADK event transcript. It does not
call a provider, start an ADK service, or spend tokens.
