# LangGraph Integration

Status: experimental.

Install the optional dependency when running a real LangGraph graph:

```bash
pip install "agent-assure[langgraph]"
```

The optional extra uses LangGraph's stable 1.x line. The current Sprint 9
smoke target was verified against LangGraph 1.2.8 on July 7, 2026; the
integration remains experimental and does not yet maintain a broader version
matrix. The adapter itself can be imported without LangGraph installed so
tests and fixture examples stay offline.

## How It Works

`LangGraphAdapter` reads `agent_assure` metadata from LangGraph events or
streamed node updates. It ignores raw event `data.input`, `data.output`,
messages, completions, and tool arguments. Application nodes should emit only
privacy-filtered metadata, using compact labels or digests for
`privacy_filtered_attributes`, top-level labels such as `provider`, `model`,
`tool_name`, and `review_route`, and usage labels such as `operation` and
`cost_basis`, such as:

```python
{
    "agent_assure": {
        "case_id": "lg-exp-001",
        "event_type": "tool_call",
        "sequence_number": 2,
        "tool_name": "expense_policy_lookup",
        "evidence_refs": ["ref-expense-policy-v3"],
        "redaction_state": "redacted",
        "privacy_filtered_attributes": {
            "policy_version": "expense-policy-v3"
        },
    }
}
```

The adapter converts those events into `FrameworkObservation` values, then into
ordinary `AgentRunRecord` artifacts. From that point onward, the normal
agent-assure evaluator checks expected recommendation/outcome, required
evidence, material claim links, provider/tool boundaries, review routing, and
redaction controls. Parallel LangGraph update events with multiple node
updates produce one observation per node when each node carries
`agent_assure` metadata. Those parallel node observations must use distinct
`sequence_number` values.

The current projection helper emits fixture-mode review artifacts only. Do not
use it to label stochastic production traffic as live evidence; protocol-bound
live runs must go through the live runner.

## Offline Example

The repository includes `examples/langgraph_expense_assurance`. The baseline
keeps the final decision, required policy evidence, human-review route, and
provider/tool boundary. The candidate keeps the same final decision but omits
the required policy evidence reference, so it fails deterministic process
invariants.

```bash
python examples/langgraph_expense_assurance/run_example.py
```

The example runs offline. If LangGraph is installed, it builds and streams a
small `StateGraph`; otherwise it reports `fallback-no-langgraph` in the JSON
summary and uses the same deterministic stream shape so adapter and evaluator
behavior remain testable without network or token spend.
