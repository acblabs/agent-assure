# LangGraph Expense Assurance

This experimental example shows a framework adapter translating LangGraph node
updates into privacy-filtered `AgentRunRecord` artifacts. The baseline and
candidate keep the same final recommendation and review route, but the
candidate omits the required policy evidence reference, so deterministic
evaluation blocks the process regression.
The final recommendation and outcome are read from observed decision-node
metadata, not from the static projection helper.

Run it from the repository root:

```bash
python examples/langgraph_expense_assurance/run_example.py
```

The example is offline and synthetic. It does not persist raw prompts, raw
model completions, raw tool arguments, or unredacted summaries.
