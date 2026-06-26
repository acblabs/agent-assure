# Fixture Mode

Fixture mode holds model outputs, tool outputs, and suite inputs constant. The
current implementation validates, compiles, manifests, and runs fixture-mode
suites without provider SDKs or network calls.

Fixture paths are resolved relative to the suite root and cannot escape it.
Suites may declare multiple fixture roots. Each root must use the `requests`,
`model_outputs`, and `tool_outputs` subdirectories, and each case fixture ID
must resolve to exactly one complete triplet across all declared roots. Fixture
manifests store POSIX-normalized relative paths, byte sizes, and SHA-256 file
digests. Run records carry the fixture manifest digest in provenance so
baseline and candidate variants can prove they used the same fixtures.

Compiled-suite source digests can be verified during fixture runs when the
source YAML is supplied or can be inferred from the suite root.

The fixture runner is in-process. Ordinary Python exceptions are captured as
`runtime_error` run records with `RUNTIME_FAILED`; catastrophic process
termination such as segmentation faults or `os._exit` is outside the current
runtime boundary.

The test configuration runs pytest with socket creation disabled. This backs the
offline fixture-mode claim with a process-level guard in addition to targeted
network regression tests.
