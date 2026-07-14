# Streaming Process Regression Example

This fixture shows streaming-process assurance when the final decision fields stay
unchanged.

Run a scenario:

```powershell
agent-assure stream ingest examples/streaming_process_regression/events/candidate_evidence_removed.jsonl --sequence-scope global --out .tmp/streaming/stream-run.json
agent-assure stream evaluate .tmp/streaming/stream-run.json --suite examples/streaming_process_regression/suite.yaml --out-dir .tmp/streaming/report
```

Scenarios:

- `baseline.jsonl`: evidence is linked before the final answer and review is routed.
- `candidate_evidence_removed.jsonl`: final answer is identical, but the evidence link is removed before completion.
- `candidate_review_bypassed.jsonl`: final answer is identical, but required review is bypassed.
- `candidate_retry_burst.jsonl`: final answer is identical, with repeated retry events and measured usage before completion. This scenario exits 0 under the bundled suite because retries are surfaced as review evidence unless a suite or policy declares a blocking retry threshold.
