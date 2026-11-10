# Proposed first Sprint 3 dispatch

The S1/S2 development close is complete; see the
[accepted handoff](../sprint2/closure-status.md). This directory prepares the
next editing dispatch. It does not change the accepted design or authorize
production edits.

The [exact scope proposal](schema-dispatch-proposal.json) covers only
SCHEMA-01A and SCHEMA-01D. It enumerates source, tests, documentation and every
generated path, including the 42-contract resource set and compatibility matrix.
The map extends the existing validation registry; it does not create a second
compatibility dispatch registry. Existing v0 snapshots and the 0.6.6 legacy
writer/default exports remain protected.

The proposed new writer is `1.0.0rc1`; the distinct proposed preview-reader
package is `1.0.0a3`. Neither identity is published or implemented. A development
wheel whose metadata still says 0.7.0 cannot prove that the released 0.7.0 reader
supports these new records. The proposed metadata changes are limited to the
new preview identity and packaging resources; dependencies remain outside scope.

There is a pre-dispatch bootstrap cycle: the roadmap requires a signed
`dispatch-context/v1` before editing, while its production first writer requires
the SCHEMA-01D receipt that this first dispatch is meant to earn. The
[proposed additive decision](../../../adr/0024-v1-schema-bootstrap-dispatch.md)
defines a temporary planning route for A/D only, with the same source, receipt,
scope, signature and resource safeguards. It creates no runtime authority and
sunsets at SCHEMA-01D acceptance. It remains unaccepted.

Before editing, the maintainer must adopt that exact decision and approve the
concrete file map, accountable owner/reviewer assignment and work limits.
`acblabs` is proposed as accountable platform owner and maintainer reviewer in
`maintainer_development` mode. Capacity and backup are not inferred from the
separate 24/7 support-policy commitment. The assignment, conflicts and sufficient
review capacity must be explicitly adopted. No independent reviewer is claimed.

The forecast also requires a scoped rebaseline/reconfirmation now that a
concrete surface is proposed. The accepted forecast remains unchanged. Its
existing estimate is shown for comparison; no selected value or human estimate
decision is fabricated.

The existing whole-ticket forecast is 70 engineering hours at P50, 174 at P90,
and 62 reviewer hours at P50, with low confidence. It includes A/B/C/D; these
figures are not an A/D-only estimate. The first proposal resolves only A/D's
135 paths. B/C's unresolved scope remains work, and no proportional allocation
or reduction of the whole-ticket estimate is implied. A scoped rebaseline must
record how the concrete first wave and remaining work affect those assumptions.

The package identity change also requires eleven explicitly listed current
report fixtures to refresh their producer/evaluator version metadata and derived
hashes. Their conclusions, scores and behavior remain protected. Historical
version-labelled fixtures and oracle implementations are excluded. An unexpected
semantic difference requires a separate reviewed decision.

After those decisions, a private packet and trusted generator/verifier can be
prepared, reviewed, adopted and signed for the exact source. Editing starts only
after that verification passes. A/D completion still needs installed-wheel and
compatibility evidence and exact implementation receipts. B/C, TEMP-01A and
other Sprint 3 tickets have no editing scope under this proposal.
