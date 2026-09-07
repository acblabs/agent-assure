# Threat Model

`agent-assure` is an offline-first assurance tool. Its main security boundary is
between trusted repository artifacts and untrusted run or adapter output. It
helps detect governance regressions in structured records; it does not sandbox a
malicious model, script, provider, CI checkout, or operator.

The bundled demos also install a Python-level `sitecustomize` socket guard and
use a minimized subprocess environment. Those controls reduce accidental
network use by trusted demo code; they are advisory defense-in-depth and are not
a network-isolation boundary against hostile Python or native code.

## Trusted Inputs

- Compiled suites, expectations, fixture manifests, policy bundles, and release
  replay files are treated as repository-controlled review artifacts.
- Controls-mutation configurations and threat-applicability manifests are also
  repository-controlled review artifacts. Threat applicability, criticality,
  present-control declarations, review dates, owners, and rationales are
  authored governance inputs; the engine does not discover or independently
  verify them.
- Fixture mode is deterministic and offline. The runner constructs records from
  local fixtures and recomputes built-in controls during evaluation.
- Live mode treats the configured adapter, static JSONL file, external script,
  or network provider as a trusted producer of observation data. A compromised
  producer can still fabricate recommendations, evidence links, claims, tools,
  review flags, and summaries, but live producer-supplied failing policy results
  are verdict-bearing during evaluation.
- Live artifacts may include host wall-clock timestamps, measured latency,
  scheduling jitter, provider response identifiers, and emergency-record timing.
  They are operational evidence, not byte-replay-stable fixture artifacts.

## Live Execution Boundary

- Live prompt files, static response JSONL files, external scripts, and
  external-script working directories must resolve under the live config
  directory. Absolute paths and parent-directory traversal are rejected for those
  fields.
- A caller-supplied `LiveExecutionSnapshot` is an authoritative in-process
  executable-input capability. Validation proves bounded internal consistency,
  exact content digests, and compatibility with configured semantic bindings;
  it does not prove that detached bytes came from, or still match, the mutable
  paths named by the config when those paths have no configured content digest.
  Callers crossing a trust boundary must prepare snapshots themselves with
  `prepare_live_execution_snapshot`; same-process library callers are trusted.
  The supported repeated-study CLI prepares snapshots from rooted paths and
  never accepts detached snapshots from its input files.
- The external-script adapter runs without a shell and receives only declared
  environment variables plus runner-injected request and trace context. It is
  not a sandbox; the configured script still executes with the caller's host
  privileges and can access caller-readable files and networks regardless of an
  endpoint declaration. Prompt-driven CLI runs (without `--trust-config`) require
  a separate default-deny confirmation for external-script execution, declared
  live network access, and selected host environment variables whenever the
  config requests those capabilities. The prompts identify the configured script,
  the endpoint host for endpoint-bound adapters, and environment-variable names
  without displaying their values; sensitive-looking configured display text is
  redacted. Non-interactive CI runs must
  pass `--trust-config` plus the matching risk-specific flags
  (`--allow-external-script`, `--allow-network`, and/or `--allow-script-env`);
  `--ci` alone only suppresses prompts and does not grant trust. CI network
  runs also require endpoint DNS safety screening to succeed.
- External-script stdout/stderr are streamed through byte-counting pipe readers.
  Oversized output terminates the child and is rejected as invalid output;
  emergency records store only byte counts and redacted summaries.
- The OpenAI-compatible adapter requires `allow_network: true`, HTTPS, an API
  key environment variable, and an endpoint host allowlist. `api.openai.com` is
  allowed by default; non-default gateways must be listed explicitly in
  `allowed_endpoint_hosts`. Localhost, private, link-local, reserved, multicast,
  and unspecified endpoint hosts are rejected by literal host inspection and
  by resolved A/AAAA records. Any CLI live run whose config enables
  `allow_network: true` requires endpoint DNS safety screening to succeed;
  `--strict-endpoint-resolution` is retained for CLI compatibility only.
  Endpoint-bound network adapters always fail closed when endpoint hosts cannot
  be resolved for screening.
  OpenAI-compatible requests repeat DNS screening immediately before dispatch
  and connect only to one of those screened addresses while retaining the
  original hostname for TLS verification and the HTTP Host header. This is
  per-request address pinning, not certificate/public-key pinning.
- OTLP HTTP export is explicit operator-controlled network egress. OTLP export
  requires an explicit HTTPS endpoint and an explicit endpoint-host allowlist;
  SDK environment-default endpoints, headers, credential-provider sessions,
  client certificates, and proxy configuration are not used. The project-owned
  HTTP session disables redirects and ambient Requests configuration. Localhost, private,
  link-local, reserved, multicast, and unspecified endpoint hosts are rejected
  by literal host inspection and by resolved A/AAAA records. OTLP endpoint DNS
  screening fails closed when resolution is unavailable. The upstream exporter
  resolves again when connecting, so OTLP retains a documented DNS
  validation-to-connect TOCTOU window and does not provide address-level
  pinning.

## Privacy Boundary

- Persistence and reporting apply pattern-based redaction to common identifiers,
  emails, payment-card-like numbers, DOB patterns, bearer/JWT/API-key-like
  tokens, selected cloud/source-control tokens, secret-looking key/value pairs,
  and URL query secrets.
- RunSet writes also fail closed when schema-preserved decision fields,
  identifiers, provider-response IDs, provider/model provenance labels, pricing
  labels, evidence identifiers, script names, or debug references contain
  sensitive-looking values. This protects fields that are otherwise preserved
  for artifact stability.
- Evaluation recursively scans persisted run-record strings for sensitive-looking
  content while skipping digest/hash/provenance metadata. This is a guardrail,
  not production PHI de-identification or comprehensive DLP.
- Privacy scanning includes mapping keys and fails closed on individual scalar
  values above the bounded detector budget. It scans a second, profile-bound
  Unicode deobfuscation view so bidi, zero-width, private-use, surrogate, and
  other category-C code points cannot split an otherwise detectable email,
  identifier, or credential. Unicode dash equivalents are normalized for SSN
  and card scans, and non-ASCII text bypasses literal-marker pruning. Every
  non-empty value under a recognized structured sensitive label fails closed;
  non-ASCII structured keys with non-empty scalar values also fail closed.
  OpenTelemetry export repeats the recursive
  sensitive-content check at the final egress boundary and applies
  explicit span, event, attribute, key, and value limits. Its SDK resource,
  trace propagator, root context, sampler, span limits, and OTLP compression are
  explicitly constructed rather than selected from ambient SDK settings.
  Exporter failure results, exceptions, incomplete flushes, shutdown failures,
  or missing exported spans fail the operation instead of being logged as
  success.
- Raw prompts and raw provider responses are not persisted in RunSet artifacts,
  but a trusted live adapter or external script sees the prompt it is asked to
  process.
- Optional usage artifacts may persist measured token, tool-call, retry,
  latency, and declared estimated cost fields. Cost-bearing usage segments must
  include explicit limitations, and pricing snapshot IDs, pricing snapshot
  digests, or cost-basis labels are treated as observable metadata for review
  rather than proof of business impact. Future renderers that show segment
  metadata labels directly should route those labels through redaction.
- The bundled fixture HMAC key is synthetic-example-only. Its use requires the
  compiled-suite digest, complete fixture-manifest digest, and runner identity
  to match reviewed, pinned constants for a bundled example. Each fixture is
  parsed from the same byte buffer whose size and digest are rechecked against
  the approved manifest. Non-synthetic or modified fixture runs must provide an
  explicit key of at least 32 bytes rather than reusing the public repository
  default.

## Release Boundary

- Digest replay checks repository reproducibility and manifest-listed artifact
  digests. It is not a signature.
- Keyless cosign bundles bind exact release bytes to the GitHub Actions workflow
  identity when downstream verification pins the repository, workflow file, ref,
  commit, workflow name, and trigger.
- Release evidence does not establish safety assurance, regulatory compliance,
  clinical validity, live model quality, or dependency vulnerability status.

## Empirical Study and External-Pilot Boundary

- Study finalization and config binding are no-dispatch operations. They do not
  authorize provider use, network access, credential access, or budget spend.
  Provider execution remains behind the existing explicit live-run consent and
  configuration controls.
- A study manifest's self-digest and declared registration evidence detect
  mismatched content but are not signatures or independent timestamps. The
  implementation does not contact a version-control host or append-only
  registry to verify the declared reference, immutability, actor, or
  registration time. The mandatory pre-execution receipt records explicit
  human attestations for reference resolution, exact byte/digest agreement,
  immutability, coverage, and time ordering; reviewer identity and remote truth
  are still verified out of band.
- Provider, requested/resolved model, API, SDK, region, adapter, and pipeline
  identities are checked against persisted observations. They remain producer
  and adapter claims, not remote-provider attestations. A compromised adapter
  or provider can fabricate them.
- Post-registration protocol, model, configuration, benchmark, decision-rule,
  or execution-window drift invalidates confirmatory analysis. Digest binding
  does not prove that unrecorded executions were not run or that one result was
  not selected from repeated executions under identical commitments.
- External-pilot records bind environment-control, input, command, artifact,
  consent, friction, and remediation evidence. The schema checks their internal
  relationships but cannot attest repository ownership, operator independence,
  consent authority, or execution truth.
- The publish gate verifies every file in one closed, bounded, link-free pilot
  bundle, validates the tested wheel identity and supported schema contracts,
  and requires a later human independence-review receipt bound to the exact
  evidence and artifact manifest. The receipt deliberately records
  out-of-band, non-machine-verified reviewer authentication; it is not a
  signature and does not resist a hostile producer without separate
  organizational signature/OIDC and approval controls.
- A pre-candidate pilot is permanently marked learning/remediation-only and is
  ineligible for clean-reproduction, exact-candidate, and CI-integration release
  gates. Reusing its digest cannot upgrade that evidence class.

## Assurance Mutation Boundary

- Built-in mutation operators are trusted package code identified by version,
  implementation digest, declared compatible schemas, preconditions, and
  permitted changed paths. The implementation digest is an identity anchor,
  not an independent code review.
- The engine validates the source and transformed subject, works from an
  immutable copy, and fails closed when an undeclared path changes.
- A mutation is caught only when its expected-detection contract matches an
  observed finding from the target control and the declared gate effect. An
  unrelated parse, schema, runtime, or policy failure does not count.
- Control-efficacy projection consumes only a validated campaign generation and
  a catalog with matching identity and digest. It binds its report to the
  campaign, source, suite, catalog, and threat-manifest digests and validates
  exact outcome partitions, ratios, strata, survivor IDs, and threat counts.
- The ratio denominator contains only caught and survived applicable outcomes.
  Invalid, error, inapplicable, and pending work stays visible and cannot be
  relabeled as detector success. A zero denominator remains explicitly
  undefined.
- Critical operator status is derived from applicable critical threat
  references in the bound manifest. Independent challenge counts admit only
  external pre-existing, third-party-contributed, and first-party-precontrol
  provenance; first-party-postcontrol and unknown provenance remain visible but
  ineligible.
- Efficacy semantic state and configured gate effects are separate. Required
  and critical survivors, invalid/error outcomes, and required non-verdict
  outcomes have block-only policy fields. Report validation prevents internal
  arithmetic or binding contradictions; it does not establish that the
  authored threat scope is complete or correctly classified.
- Efficacy-aware CLI and programmatic gates default to strict verification when
  efficacy evidence is present. Presence is verifier-controlled separately:
  `--require-efficacy` requires a packet to contain efficacy evidence and an
  external verifier policy implies that requirement. Optional absence is
  reported as `efficacy_evidence=absent` and
  `efficacy_verification=not_requested`, never as a strict efficacy pass.
- Strict verification requires a verifier-owned controls-mutation YAML. The
  verifier policy pins the installed catalog digest, exact selected and
  required operator sets, and the separately loaded threat-manifest digest.
  The gate also cross-checks report projections against verifier-owned catalog
  and manifest semantics, including independence class, invariant family,
  threat and target-control mappings, applicability, criticality, and
  present-control scope; digest-string equality alone is insufficient.
  Acceptance uses a positive allow-list: all evaluated applicable operators
  were caught, all applicable threats were challenged, the verifier decision
  passes, and no invalid/error or required non-verdict state exists. The
  packet's embedded profile remains provenance and cannot select the strict
  acceptance policy. Gate decisions record the evidence-presence,
  verification-mode, and efficacy-required facts so strict and advisory output
  cannot be confused.
- Verifier policy files and their referenced threat manifests use the confined
  input policy. Linked or reparse-point ancestors and multiply hardlinked final
  files are rejected, which intentionally fails closed for symlinked checkout
  roots and hardlinked policy inputs. Explicit Windows UNC paths are rejected;
  mapped drive letters and Unix network mounts are not independently detected
  and remain part of the trusted host/filesystem boundary.
- Existing reports and packets are not execution attestations. Gate validation
  re-derives decisions and verifies schema/digest relationships but does not
  rerun mutation operators. A protected CI workflow making an efficacy
  assurance claim must regenerate campaigns and efficacy reports from pinned
  inputs, and repository protections should require review for the verifier
  policy, threat manifest, operator selection, and workflow.
- Operator execution does not load caller-supplied executable plugins, invoke
  caller-supplied shell text, or require network access.
- Reports minimize content to paths, digests, reason codes, bounded summaries,
  provenance, and limitations.
- Fixed mutation outputs are staged before commit, replacement failures roll
  back the prior generation, stale transformed subjects are removed, and the
  source RunSet may not alias a fixed output through a path, symlink, junction,
  or hardlink.

## Out Of Scope

- Host isolation for malicious local scripts or compromised CI jobs.
- Attestation of arbitrary live adapters, network providers, or model responses.
- Certificate/SPKI pinning, provider-side compromise detection, or MITM
  detection beyond HTTPS, endpoint host allowlisting, and DNS safety screening.
  The OpenAI-compatible adapter does pin each request socket to a screened
  address; OTLP does not and retains the documented validation-to-connect DNS
  TOCTOU window.
- Comprehensive secret discovery, PHI de-identification, malware detection, or
  supply-chain attestation beyond digest replay and optional cosign signing.
- Isolation from a malicious installed package or compromised built-in
  operator implementation.
- Discovery of every possible control bypass or failure mode.
- Independent validation of an authored threat-applicability manifest,
  organizational criticality decision, or required-operator selection.
- Protection against a malicious change that is authorized to modify both the
  verifier-owned policy inputs and the CI workflow that consumes them.
