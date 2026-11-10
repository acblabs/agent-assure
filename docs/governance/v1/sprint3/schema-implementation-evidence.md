# Schema implementation evidence

Status: **in progress; no SCHEMA-01A or SCHEMA-01D implementation acceptance**.
This records development evidence and limitations. It grants no qualification,
method admission, release or deployment authority.

## Dispatch basis

- Work packages: SCHEMA-01A and SCHEMA-01D under the accepted bootstrap exception.
- Parent packet digest: `sha256:4b4ac646506d0167c5b9c0ee557d9e79a4ba81e0faba7ee55f870b0b2a56aa28`.
- Additive test/profile amendment: `sha256:6c40be1d9a271823cacd65b42784a32e20ad22f40d484c75fd6dfadb55d1e7af`.
- The maintainer's actual native signature verified before amended execution.
- Development owner/reviewer: acblabs; `NO_INDEPENDENT_REVIEW` remains explicit.
- The original four-hour checkpoint and trust expiry were not renewed.

## Implemented increment

- Immutable exact four-key cells, bounded versions, explicit dispositions,
  minimum-reader checks, original-byte resource hashes and binary-search lookup.
- Bounded duplicate-rejecting matrix loading with explicit array-to-tuple
  conversion and strict scalar handling.
- Installed-reader discovery in the existing validation module. Raw METADATA
  and RECORD are bounded before parsing; arbitrary RECORD entries are not
  followed. Selected module and metadata bytes must match their owned hashes.
  Provenance belongs to the exact distribution, and directory/VCS installs fail.
- Pinned installed matrix and schema discovery, minimum-reader-before-resource
  ordering, actual identity constraint checks and offline reference handling.
- Existing frozen-root policy remains the semantic ceiling. No migration or
  declared semantic loss gains eligibility. Every result has effect `none`.
- A pure deterministic matrix builder expands fourteen verified legacy
  producer/writer pairs against the existing policy and hashes unchanged source
  snapshots. It adds the preview producer only after its actual version choice.

The default package/writer versions, existing writer models, legacy validation
functions, default exports and released schema bytes are unchanged. No new
production v1 contract is registered. New-writer cells remain absent.

## Validation observations

The retained local command observations include fresh signature/input checks,
scope checks, immutable environment checks and resource supervision. They are
local development observations; hosted validation must bind its own source.

| Check | Observation | Result |
| --- | --- | --- |
| Hardened compatibility, matrix and bounded storage tests | FocusedA006; approved command 11 | 180 passed |
| Ruff across the assigned checkout | LintA004; approved command 7 | Passed |
| Strict mypy across source and scripts | TypesA005; approved command 8 | 301 files passed |
| Existing schema regression suite | SchemaA002; approved command 2 | Failed: 78 failed nodes and 37 setup-error nodes |
| Documentation alignment | DocsA001; approved command 9 | Failed at Git discovery and existing filesystem-root access |

The bounded storage test produced a prospective matrix with 432 cells covering
14 legacy producers, 12 writer versions and reader `1.0.0a3`. Its 380,685 bytes
have exact-file digest
`sha256:9c90a00a6d3d7783786a7934805d4c53570b26ab157afd89c68ffd26fe86f33d`.
That privately retained review artifact is not an installed or accepted resource.
Documentation alignment could not inspect Git-tracked assets/action pins or
derive the existing flagship showcase facts in this execution profile. Its
failure is retained; it is not waived by the focused test results.

The broad failure report identifies existing filesystem-root ancestor-handle
denials in the current sandbox and unavailable bare Git in its closed PATH.
Read-only probes with GENERIC_READ, FILE_READ_ATTRIBUTES and zero access all
failed at the denied ancestor; they succeeded at the assigned workspace root.
No security pins were removed, tests skipped, permissions widened or candidate
commands elevated. This failed report is not a successful regression gate.

## Remaining acceptance work

SCHEMA-01A still needs reviewed packaged matrix/resources, installed-wheel
evidence, complete compatible-host checks and its actual human acceptance.
SCHEMA-01D still needs the exact 42 closed schemas, canonical projections,
instance/dependency graph checks, generated-resource review and its own human
acceptance. No first-writer or dependent TEMP-01A dispatch is authorized by this
document. SCHEMA-01B/C, publication and qualification remain deferred.

A compatible isolated runner is required for the full regression gate. The
repository's existing Windows CI configuration provides a handoff reference;
no remote run or new runner was created in this development observation.
