# Threat Model

`agent-assure` is an offline-first assurance tool. Its main security boundary is
between trusted repository artifacts and untrusted run or adapter output. It
helps detect governance regressions in structured records; it does not sandbox a
malicious model, script, provider, CI checkout, or operator.

## Trusted Inputs

- Compiled suites, expectations, fixture manifests, policy bundles, and release
  replay files are treated as repository-controlled review artifacts.
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
- The external-script adapter runs without a shell and receives only declared
  environment variables plus runner-injected request and trace context. It is
  not a sandbox; the configured script still executes with the caller's host
  privileges. Interactive CLI runs ask for explicit trusted-config
  acknowledgement before running external scripts, live network configs, or
  configs that pass host environment variables. Non-interactive CI runs must
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
  `--strict-endpoint-resolution` is retained for CLI compatibility and future
  endpoint-screened paths. With current network adapters, unresolved endpoint
  hosts already fail closed whenever `allow_network: true`.
  OpenAI-compatible requests repeat DNS screening immediately before dispatch,
  but this is not TLS pinning or socket-level IP pinning.
- OTLP HTTP export is explicit operator-controlled network egress. OTLP export
  requires an explicit HTTPS endpoint and an explicit endpoint-host allowlist;
  SDK environment-default endpoints are not used. Localhost, private,
  link-local, reserved, multicast, and unspecified endpoint hosts are rejected
  by literal host inspection and by resolved A/AAAA records. OTLP endpoint DNS
  screening fails closed when resolution is unavailable.

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
- Raw prompts and raw provider responses are not persisted in RunSet artifacts,
  but a trusted live adapter or external script sees the prompt it is asked to
  process.
- Optional usage artifacts may persist measured token, tool-call, retry,
  latency, and declared estimated cost fields. Cost-bearing usage segments must
  include explicit limitations, and pricing snapshot IDs, pricing snapshot
  digests, or cost-basis labels are treated as observable metadata for review
  rather than proof of business impact. Future renderers that show segment
  metadata labels directly should route those labels through redaction.
- The bundled fixture HMAC key is synthetic-example-only. Non-synthetic fixture
  runs must provide an explicit key rather than reusing the repository default.

## Release Boundary

- Digest replay checks repository reproducibility and manifest-listed artifact
  digests. It is not a signature.
- Keyless cosign bundles bind exact release bytes to the GitHub Actions workflow
  identity when downstream verification pins the repository, workflow file, ref,
  commit, workflow name, and trigger.
- Release evidence does not establish safety assurance, regulatory compliance,
  clinical validity, live model quality, or dependency vulnerability status.

## Out Of Scope

- Host isolation for malicious local scripts or compromised CI jobs.
- Attestation of arbitrary live adapters, network providers, or model responses.
- TLS pinning, socket-level IP pinning, provider-side compromise detection, or
  MITM detection beyond HTTPS, endpoint host allowlisting, and DNS safety
  screening.
- Comprehensive secret discovery, PHI de-identification, malware detection, or
  supply-chain attestation beyond digest replay and optional cosign signing.
