# Security

Please report suspected vulnerabilities through GitHub Private Vulnerability
Reporting at
<https://github.com/acblabs/agent-assure/security/advisories/new>. Do not open a
public issue for an unremediated vulnerability. If that private form is
unavailable, contact the repository owner listed in `.github/CODEOWNERS`
through an established private channel. If no private channel is available,
request one without including exploit details in a public channel.

The reporter-facing fallback above is not the operational escalation fallback.
The operational owner must route the private reporting inbox to a continuously
covered, 24/7 primary security on-call role and to an independent fallback
on-call role. The people on duty and their private destinations are maintained
in the access-controlled incident-response system, not in this repository.

## Vulnerability Intake and Response Objectives

The normative intake policy is
`agent-assure/security-vulnerability-intake/v1`. Its clock starts at the earlier
of `report_received_at_utc` and `internally_detected_at_utc`. It is continuous:
forwarding a report, confirming its validity, opening a different record, or
changing severity must not reset the clock. When a report credibly alleges a
Critical trigger but severity remains uncertain, apply the Critical objectives
until a named incident owner records evidence for a lower severity.

| Severity at receipt or detection | Primary page | Human acknowledgement | Initial severity and exposure assessment | Affected supported deployment response |
| --- | --- | --- | --- | --- |
| Critical | Immediate; confirm delivery within 5 elapsed minutes | Within 1 elapsed hour | Within 4 elapsed hours | Verified containment, verified no supported exposure, or safe-state entry within 4 elapsed hours |
| High | Immediate | Within 4 elapsed hours | Within 24 elapsed hours | Verified containment, verified no supported exposure, or safe-state entry within 24 elapsed hours |
| Medium or Low | Normal private intake | Within 3 business days | Within 7 business days | Track remediation and any required containment through normal governance |

Critical and High objectives use elapsed UTC time and do not pause overnight,
on weekends, or on holidays. The severity-specific objectives take precedence
over the general three- and seven-business-day targets. These are operational
response objectives, not promises that a correction will be published within
the same period.

For a Critical signal, the primary route must page immediately. Failure to
confirm delivery within 5 elapsed minutes, an unavailable Private Vulnerability
Reporting service, or any other primary-route outage activates the independent
fallback immediately. If no human acknowledges the primary page within 15
elapsed minutes, page the fallback even when delivery was confirmed. The
fallback must use a distinct person and durable route and must not depend solely
on the same GitHub account, identity provider, or notification path as the
primary. Missing coverage, missed deadlines, or failed escalation are incident
control failures: escalate them, preserve their UTC timestamps, and place any
potentially affected supported deployment in its documented safe state no later
than the applicable containment-or-safe-state objective if exposure cannot be
bounded and effectively contained.

The [security correction containment and risk-acceptance
process](docs/security_release_containment.md) defines the evidence, approval,
and safe-failure requirements. A referenced organizational incident-response
policy may impose stricter objectives. It may replace these objectives only if
the public policy identifies its immutable policy ID and revision, scope, owner,
and explicit precedence; an unreferenced private process cannot silently weaken
this contract.

Do not place production secrets, raw prompts, raw model outputs, tool arguments,
or sensitive identifiers in fixtures or persisted artifacts.

## Supported Versions

Only the latest published stable patch on the current minor release line is in
active maintenance scope. Active maintenance means that private reports are
triaged and mitigations or corrections are coordinated; it does not promise an
immediate patch publication. A correction may wait for the next standard release.
Older patch and minor lines are outside that scope unless a security advisory
explicitly says otherwise. Unreleased candidates are not supported releases and
must not be represented as such.

| Version | Security-maintenance status |
| --- | --- |
| 0.7.0 | Supported upon publication; unsupported before publication |
| 0.6.5 | Supported only until 0.7.0 is published; unsupported thereafter |
| 0.6.4 and earlier | Unsupported |

These publication-conditional rows are intentionally true both before and
after publication; they do not claim that v0.7.0 is already published. The
final prepublication release commit must update the target and immediately
preceding rows to this conditional form. The production
`check_version_matches_tag.py --require-stable` check rejects a missing, stale,
duplicated, or non-conditional transition before a tag can be created.

Every published release, including a security-only patch, uses one fail-closed
path selected by a committed, version-bound claim profile. The v0.7.0 path must
pass its bounded-claim check, strict deterministic synthetic control-efficacy,
engineering, build, provenance, signing, and Trusted Publishing gates. It has
no workflow-dispatch profile selector and no maintenance publication bypass.
`make empirical-readiness` is a separate fail-closed qualification gate for
publishing corresponding empirical results; it is not a software-distribution
gate for this bounded release.

The v0.7.0 release line is bounded to engineering qualification and committed deterministic-fixture artifact validation. No real-model study, qualifying external pilot, independent empirical review, or frozen confirmatory benchmark is included. The release therefore makes no empirical-effectiveness, external-validity, population-generalization, production-control-effectiveness, provider-quality, safety, compliance, or deployment-fitness claim. Those artifacts are prerequisites only for the corresponding empirical claim, not for distribution of this bounded release.

An unsatisfied active, version-bound release gate leaves the correction
unpublished; it cannot be waived by changing the claim profile at dispatch.
When that delay leaves a supported deployment exposed, activate the
[security correction containment and risk-acceptance
process](docs/security_release_containment.md). The process requires verified
compensating controls, tested monitoring, a named accountable owner, a distinct
authorized security approver, customer and advisory coordination, an explicit
UTC expiry, and an auditable private record. It may authorize only temporary
operation of the precisely scoped deployment. It cannot authorize a merge,
tag, signature, GitHub Release, TestPyPI or PyPI publication, or any release-gate
exception. An expired, incomplete, or unapproved record authorizes nothing.

`CODEOWNERS` routes changes across the complete package, test, workflow, script,
schema, and documentation surfaces to `@acblabs`. It is an ownership and routing
inventory, not proof that review occurred. The default branch may remain
unprotected. Before a release-sensitive update reaches it, an authorized human
maintainer must explicitly approve the candidate's full 40-hex commit SHA after
required CI passes and retain that SHA-bound authorization plus the check-run
URLs or IDs in an auditable repository or change-management record. For
agent-authored work, the human owner may provide that authorization through the
same `@acblabs` identity; describe it as human owner authorization, not
independent review or an enforced branch control. Privileged release
environments remain protected with required reviewers. Default-branch
authorization does not waive a publication gate. It is human owner
authorization for the bounded software release, not independent empirical
review and not authorization to make an empirical claim.

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
- Live adapters and providers are trusted record producers. Structured fields
  carry an origin label, but `instrumented_adapter` is still producer-attested,
  not remote attestation. Direct model self-report and legacy unspecified live
  fields cannot satisfy observation-grade tool, evidence, policy-result, or
  human-review controls. The tool does not attest provider behavior.
- Pattern redaction is a guardrail, not comprehensive DLP or PHI
  de-identification.
- The bundled demo's Python `sitecustomize` network guard is advisory
  defense-in-depth for trusted bundled code, not a sandbox or network-isolation
  boundary. Demo subprocess environments are minimized, but hostile code can
  bypass Python-level monkeypatches.
- HTTPS, endpoint allowlisting, and DNS safety screening reduce SSRF risk. The
  OpenAI-compatible adapter caches one screened authority only until the
  resolving request's fixed monotonic deadline; every request pins its socket
  to one of those screened numeric addresses while preserving hostname
  verification, and a request after expiry must screen again. This is address
  pinning, not certificate/SPKI pinning or protection from a resolver already
  compromised at screening time. OTLP HTTP export likewise binds its private
  HTTPS connection pool to the exact screened address set while retaining the
  configured hostname for SNI and certificate verification; redirects,
  proxies, ambient credentials, and connections outside that authority fail
  closed. Each OTLP HTTP request also has a monotonic socket watchdog and a
  65,536-byte decoded response ceiling; a separate process deadline is still
  required to bound a complete multi-request export command.

## Operator Guidance

- Prefer fixture and static JSONL modes for untrusted pull requests.
- Do not enable `external-script`, `allow_network`, or `script_env_allowlist`
  for forked or otherwise untrusted CI jobs.
- In non-interactive live CI, require `--trust-config` plus the matching
  risk-specific flags. For OpenAI-compatible egress, independently supply the
  exact `--authorized-endpoint-host` and `--authorized-api-key-env`; never derive
  those flags from the live config under review. Keep endpoint DNS screening
  strict. First-party RunSets and their evaluation summaries record only that
  authorized host and environment-variable name, never the credential value.
- Treat `requirements*.lock`, `requirements-min.constraints.txt`,
  `.gitleaksignore`, `.gitleaks.toml`, release manifests, and generated evidence
  packets as part of the reviewed release and security material. Keep
  `.gitleaksignore` suppressions scoped to exact reviewed historical fingerprints.
  A semantic `.gitleaks.toml` exception must target one rule and
  require both an anchored whole-match expression and exact artifact paths; a
  path-only, line-wide, secret-only, or `OR` exception is prohibited. Keep the
  history scan's merge-result canaries proving that the intended exception is
  narrow and that same-file, sibling-path, and unrelated-rule credentials are
  still detected. Do not remove its independent non-empty revision check or
  exact scanner/independently-enumerated patch-unit assertion: exit status
  alone is not accepted as proof that Git history was scanned completely,
  including merge resolutions. Keep its `main` push trigger free of path
  exclusions so participant-input-only commits cannot bypass it.
