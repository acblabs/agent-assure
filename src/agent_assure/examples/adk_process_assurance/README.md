# Google ADK Process Assurance

This experimental example shows a Google ADK-shaped multi-agent workflow being
translated into privacy-filtered `AgentRunRecord` artifacts. The baseline and
candidate keep the same final recommendation and required evidence, but the
candidate changes to an automatic path and reports
`human_review_required=false`, so deterministic evaluation blocks the process
regression. The built-in check measures observed human-review routing and
performed review; the route token is preserved as process evidence but is not
compared for string equality by this minimal suite.

Run it from the repository root:

```bash
python examples/adk_process_assurance/run_example.py
```

The example is offline and synthetic. It does not call a provider, start an ADK
service, or persist raw prompts, raw model completions, raw tool arguments, or
unredacted summaries.
