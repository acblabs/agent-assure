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

## Live Execution Boundary

- Live prompt files, static response JSONL files, external scripts, and
  external-script working directories must resolve under the live config
  directory. Absolute paths and parent-directory traversal are rejected for those
  fields.
- The external-script adapter runs without a shell and receives only declared
  environment variables plus runner-injected request and trace context. It is
  not a sandbox; the configured script still executes with the caller's host
  privileges.
- External-script stdout/stderr are captured through bounded temporary files.
  Oversized successful output is rejected as invalid output, and emergency
  records store only byte counts and redacted summaries.
- The OpenAI-compatible adapter requires `allow_network: true`, HTTPS, an API
  key environment variable, and an endpoint host allowlist. `api.openai.com` is
  allowed by default; non-default gateways must be listed explicitly in
  `allowed_endpoint_hosts`.

## Privacy Boundary

- Persistence and reporting apply pattern-based redaction to common identifiers,
  emails, payment-card-like numbers, DOB patterns, bearer/JWT/API-key-like
  tokens, selected cloud/source-control tokens, secret-looking key/value pairs,
  and URL query secrets.
- Evaluation recursively scans persisted run-record strings for sensitive-looking
  content while skipping digest/hash/provenance metadata. This is a guardrail,
  not production PHI de-identification or comprehensive DLP.
- Raw prompts and raw provider responses are not persisted in RunSet artifacts,
  but a trusted live adapter or external script sees the prompt it is asked to
  process.
- Optional usage artifacts may persist measured token, tool-call, retry,
  latency, and declared estimated cost fields. Cost-bearing usage segments must
  include explicit limitations, and pricing snapshot IDs or cost-basis labels
  are treated as observable metadata for review rather than proof of business
  impact. Future renderers that show segment metadata labels directly should
  route those labels through redaction.
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
- TLS pinning, provider-side compromise detection, or MITM detection beyond
  HTTPS and endpoint host allowlisting.
- Comprehensive secret discovery, PHI de-identification, malware detection, or
  supply-chain attestation beyond digest replay and optional cosign signing.
