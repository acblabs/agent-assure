# Documentation Alignment

`scripts/check_docs_alignment.py` is the shared local and CI documentation
check. It verifies claim traceability rows, schema inventory, reason-code
inventory, OTel mapping references, changelog presence, and conservative public
claim boundaries.

The forbidden-claim check is intentionally phrase-based and conservative. Avoid
release-facing wording that uses certification verbs next to safety or
compliance, even in negated sentences, because CI treats those phrases as too
easy to misread out of context. Prefer wording such as "establish safety
assurance", "prove regulatory compliance", "claim compliance status", or
"validate clinical use" only when the surrounding sentence clearly states the
project boundary.
