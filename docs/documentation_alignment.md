# Documentation Alignment

`scripts/check_docs_alignment.py` is the shared local and CI documentation
check. It verifies claim traceability rows, schema inventory, reason-code
inventory, OTel mapping references, changelog presence, and conservative public
claim boundaries. The v0.7.0 release additionally has a machine-checked,
version-bound `bounded-non-empirical/v1` profile whose canonical scope
disclosure must appear in README, CHANGELOG, SECURITY, the PyPI runbook, and the
v0.7.0 release notes.

The forbidden-claim check is intentionally phrase-based and conservative. Avoid
release-facing wording that uses certification verbs next to safety or
compliance, even in negated sentences, because CI treats those phrases as too
easy to misread out of context. Prefer wording such as "establish safety
assurance", "prove regulatory compliance", "claim compliance status", or
"validate clinical use" only when the surrounding sentence clearly states the
project boundary.
