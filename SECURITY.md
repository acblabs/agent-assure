# Security

Please report suspected vulnerabilities privately through the repository owner.

Do not place production secrets, raw prompts, raw model outputs, tool arguments,
or sensitive identifiers in fixtures or persisted artifacts.

## Supported Surfaces

Security review should assume `agent-assure` is an offline-first assurance tool,
not a sandbox for untrusted repositories, untrusted scripts, untrusted live
adapters, or malicious CI jobs.

Report issues privately when they allow unexpected code execution, data
exfiltration, secret persistence, path escape, artifact forgery across a stated
trust boundary, or network egress beyond the documented adapter and telemetry
controls.

## Intentional Boundaries

- The external-script live adapter intentionally executes configured host code
  with caller privileges. Only run it for trusted configs and trusted
  repositories.
- Live adapters and providers are trusted producers of observation records; the
  tool evaluates the records but does not attest provider behavior.
- Pattern redaction is a guardrail, not comprehensive DLP or PHI
  de-identification.
- HTTPS, endpoint allowlisting, and DNS safety screening reduce SSRF risk but do
  not provide TLS pinning, socket-level IP pinning, or protection from a fully
  compromised resolver.

## Operator Guidance

- Prefer fixture and static JSONL modes for untrusted pull requests.
- Do not enable `external-script`, `allow_network`, or `script_env_allowlist`
  for forked or otherwise untrusted CI jobs.
- In non-interactive live CI, require `--trust-config` plus the matching
  risk-specific flags and keep endpoint DNS screening strict.
- Treat `requirements*.lock`, release manifests, and generated evidence packets
  as part of the reviewed release material.
