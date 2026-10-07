# Dependency Locking

Release bundles include environment provenance, a dependency inventory, and an
SBOM that records the local release build environment and distribution file
hashes. Release workflows, TestPyPI candidate builds, and local release runbooks
install from the checked-in `requirements.lock` with
`pip install --require-hashes` before installing the package with `--no-deps`.
The lockfile path and digest are captured in the evidence packet environment
section.

## SBOM evidence profile

The release SBOM is CycloneDX 1.5 and identifies the `build` lifecycle. It
models the exact local release-build environment, not every dependency that
could be selected for every supported platform or optional adapter. A
digest-verified `pip-compile` lock supplies the dependency edges and archive
hash evidence. Runtime dependencies are `required`, separately resolved
optional-adapter dependencies are `optional`, and development/build-only
packages are `excluded`. An installed package that is not reachable through
the verified lock graph is retained as `environment-only-unclassified` rather
than silently omitted.

Each locked package component carries every SHA-256 recorded for that exact
name/version coordinate. Those are the approved source/wheel archive set in the
lock; they do **not** claim which archive produced the installed files. The
component property `agent-assure:component-hash-installed-artifact` therefore
remains `not-identified`. Built wheel and source-distribution file components
instead carry SHA-256 over their exact local bytes. Generation fails if the
recorded lock digest differs, a lock pin lacks SHA-256 evidence, or an installed
version disagrees with a coordinate present in the verified lock.

License data is included only when it is locally declared: project metadata is
read from `pyproject.toml`, and third-party SPDX expressions come only from the
installed distribution's `License-Expression` core-metadata field. Missing or
conflicting data is `unknown`. Author/publisher metadata is not reinterpreted as
a supplier, so supplier evidence currently remains explicitly `unknown`.

The SBOM also records
`agent-assure:vulnerability-analysis-status=not-performed` and
`agent-assure:vulnerability-status=unknown`. No `vulnerabilities` array is
emitted without an authenticated audit/VEX input. Consequently, absence of a
vulnerability entry never means "no known vulnerabilities." CycloneDX
composition completeness remains `unknown`: lock annotations describe the
selected build graph but do not prove a complete global supply chain.

Validate the generated profile, canonical serial, embedded paths, lock digest,
and exact distribution bytes offline with:

```bash
python scripts/check_sbom.py --sbom .tmp/release/sbom.cdx.json --artifact-root .
```

That standalone command proves structural and local-evidence consistency for
the document it is given; it does not possess a separately trusted environment
inventory or expected distribution allowlist, so it cannot by itself prove
that an attacker omitted an environment-only package or a release file. The
release-bundle path closes that boundary by passing the trusted
`EnvironmentInfo` and exact wheel/sdist path set to the validator and requiring
byte-for-byte equality with a full reconstruction. Treat only that bound path,
or an equivalent verifier supplied with the same independent inputs, as an
SBOM completeness check.

`requirements.lock` is generated from `pyproject.toml` with Python 3.14.6 and
`pip-compile --all-build-deps --extra=dev --generate-hashes`. Python 3.14 is
part of the supported CI matrix. Python 3.14.6 is the canonical producer for
release and evidence workflows until an intentional runtime-identity update or
a cross-OS reproducibility matrix is reviewed. Compatibility CI continues to
exercise the supported minor versions independently.

To refresh the lockfile:

```bash
pip-compile pyproject.toml --extra dev --all-build-deps --generate-hashes --output-file requirements.lock
```

The RFC 8785 dependency is part of the digest trust core and is pinned exactly in
`pyproject.toml`.

`requirements-min.lock` is the lower-bound compatibility profile. Its six
direct runtime dependencies are constrained to the exact minimum versions
declared in `pyproject.toml` by `requirements-min.constraints.txt`; development
and transitive dependencies still resolve normally. CI installs this
hash-verified universal lock on the oldest and newest supported Python minors
and runs the complete test suite. Before pytest, CI proves one-to-one normalized
name coverage between the runtime declarations and exact minimum constraints,
checks that the direct lock pins and installed direct versions equal those
floors, and runs `python -m pip check` over the complete installed graph. That
profile detects an understated runtime floor—and the resulting overstated
compatibility claim—without weakening the reproducible release environment
represented by `requirements.lock`.

The Pydantic floor is `2.13.0`: published study artifacts serialize with
warnings treated as errors, and `2.13.0` is the first verified release in this
profile that handles the project's discriminated decision-rule unions and
`exclude_if` fields without a false serializer warning. The Typer floor is
`0.19.0`: the CLI uses both PEP 604 unions and `typing.Literal`, and `0.19.0` is
the first Typer release that can construct that command tree. The PyYAML floor
is `6.0.3`, the first supported release in this profile that installs on Python
3.14 without relying on an unavailable source-build path.

Refresh the lower-bound profile with:

```bash
uv --cache-dir .tmp/uv-cache pip compile pyproject.toml \
  --extra dev \
  --constraint requirements-min.constraints.txt \
  --generate-hashes \
  --python-version 3.11 \
  --universal \
  --output-file requirements-min.lock
```

After controlled regeneration, refresh both lock header digests. The normal
`source-dependency-input-sha256` marker binds the project declarations, while
`minimum-runtime-constraints-sha256` additionally binds the lower-bound input.

Optional framework smoke jobs use dedicated lockfiles so the real framework
dependency is installed instead of allowing an import-gated test to skip. The
The ADK, LangGraph, and OpenTelemetry locks use universal Python 3.11
resolutions so the same checked-in files cover the Linux and Windows branches
exercised by CI and security audits:

- `requirements-langgraph.lock` covers the development and LangGraph extras;
- `requirements-adk.lock` covers the development and Google ADK extras; and
- `requirements-otel.lock` covers the development and OpenTelemetry extras.

Refresh the LangGraph smoke lock with:

```bash
uv --cache-dir .tmp/uv-cache pip compile pyproject.toml \
  --extra dev \
  --extra langgraph \
  --generate-hashes \
  --python-version 3.11 \
  --universal \
  --output-file requirements-langgraph.lock
```

Refresh the ADK smoke lock with:

```bash
uv --cache-dir .tmp/uv-cache pip compile pyproject.toml \
  --extra dev \
  --extra adk \
  --generate-hashes \
  --python-version 3.11 \
  --universal \
  --output-file requirements-adk.lock
```

The ADK CI job also performs an unconditional `google.adk.events.event` import
before pytest. A missing optional dependency therefore fails the compatibility
job instead of producing a green skip.

The OpenTelemetry extra is intentionally pinned to the exact tested 1.44.0
API, SDK, and OTLP HTTP exporter tuple because transport isolation verifies
private OTLP HTTP exporter state before export. Refresh its universal Python
3.11 lock with:

```bash
uv --cache-dir .tmp/uv-cache pip compile pyproject.toml \
  --extra dev \
  --extra otel \
  --generate-hashes \
  --python-version 3.11 \
  --universal \
  --output-file requirements-otel.lock
```

The dedicated OTel contract job unconditionally imports the API, SDK, and OTLP
HTTP exporter before running the complete telemetry SDK and OTel CLI test files
against the real SDK and exporter. Its pytest policy converts every skip into a
failure. Missing or incompatible optional dependencies therefore cannot turn
those contract tests into a successful skip.

## Source freshness and controlled regeneration

Each checked-in Python lock carries a
`source-dependency-input-sha256` header. The digest covers a canonical
projection of only the dependency-resolution inputs in `pyproject.toml`:
`build-system.requires`, `project.requires-python`, `project.dependencies`, and
`project.optional-dependencies`. Unrelated formatter, coverage, or tool
configuration changes therefore do not stale every lock. Run the offline check
with:

```bash
python scripts/check_dependency_lock_freshness.py
```

The unit regression runs under the normal `make check` test suite. A declared
dependency or supported-Python change without a corresponding marker refresh
fails repository checks. Marker freshness cannot mask semantic drift: the
checker also requires every runtime dependency to have exactly one normalized
minimum constraint, requires each constraint to equal the declared inclusive
floor, and requires the matching direct pin in `requirements-min.lock`. The
hosted lower-bound job adds `--verify-installed-minimums` and `python -m pip
check` after installation. The marker is a review aid, not proof that a resolver
produced the lock: reviewers must still inspect the resolved diff, generator
identity, hashes, platform/Python targets, hash-required installs, audits, and
release reproduction evidence.

Dependabot may propose changes to declared Python dependencies, but it does not
reliably regenerate these project-specific `pip-compile` and `uv` hash locks
across their distinct Python and platform targets. Agent Assure therefore does
not let a bot rewrite and commit transitive lock output automatically. The
strongest safe partial automation is advisory discovery plus the offline source
freshness failure; a maintainer performs the documented controlled regeneration
commands and reviews the resulting lock diffs. This deliberate limitation
avoids presenting an unaudited resolver rewrite as an approved dependency
update.

## Automated security monitoring

Dependabot checks both Python and GitHub Actions dependencies weekly. The
`security` workflow runs SHA-pinned CodeQL analysis on pushes, pull requests,
and a weekly schedule; reviews dependency changes on pull requests; audits all
five hash-locked Python dependency sets on direct updates to `main`, manual
dispatches, and a weekly schedule across Ubuntu 24.04 and Windows Server 2025
under the oldest and newest supported Python minors, 3.11 and 3.14; and scans
every reachable Git commit with a versioned, digest-pinned Gitleaks container.
The security workflow intentionally has no push path exclusion: even a
pilot-input-only update to `main` triggers the history scan. The history scan
checks out the complete repository history, independently requires a non-empty
Git revision enumeration, mounts the checkout read-only, and runs the
unprivileged scanner with no network, no Linux capabilities, and a read-only
container filesystem. Detected values are redacted, and the job fails closed
on a finding or scanner error. Before trusting the history result, an isolated
detector canary introduced only by a merge result must produce the dedicated
leak exit code. The real scan includes first-parent merge-result diffs and must
report a positive patch-unit count exactly matching an independent, unique Git
enumeration under the same merge projection (excluding deletion-only commits,
which cannot introduce a secret), with no internal Git/scanner error. An
exit-zero scan without those completeness signals is a failure. This
complements the separate scan of the
exact wheel and source distribution: neither the repository-history scan nor
the release-payload scan substitutes for the other.

Each lockfile is passed to a separate pinned audit-action invocation using only
supported action inputs. The action's requirements-file path is exercised by
its upstream Windows self-test as well as Linux. Dependency auditing requires
the recorded hashes and disables dependency resolution for each lock; the
pinned action may still create an isolated audit environment while processing
it. The OS/Python matrix evaluates environment-marker branches and published
advisories. It does not turn the Python 3.11/Linux-specific ADK and
OpenTelemetry locks into Windows or Python 3.14 installation qualifications.

Release and TestPyPI publication repeat that four-cell audit matrix against the
exact build-source SHA and require every cell to succeed. They also run the
complete lower-bound suite on Python 3.11 and 3.14 before any protected tag,
attestation, or package-publication job can run. The exact built wheel and
source distribution are scanned in a separate source-bound candidate job.

For a targeted advisory remediation, add
`--upgrade-package <distribution-name>` to each applicable compile command,
review the resulting diff to confirm that unrelated version pins did not move,
and retain only resolver- or downloader-produced hashes. Validate every changed
lock with a hash-required install and dependency audit before committing it.

These controls report published advisories; they do not prove that dependencies
are vulnerability-free. A lock update remains subject to normal tests, explicit
human-maintainer review, hash review, and release reproducibility checks.
