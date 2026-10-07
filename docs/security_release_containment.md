# Security Correction Containment and Risk Acceptance

Status: normative operational policy for supported releases.

This runbook applies when a vulnerability affects a supported release and its
correction cannot yet satisfy the standard publication gates. It creates a
controlled way to contain the exposure and, only when necessary, accept the
remaining operational risk for a short, explicit period.

The process is deliberately separate from release authorization. Use the
public
[`security_release_risk_acceptance.yaml`](templates/security_release_risk_acceptance.yaml)
as the record shape, but store the completed record and its evidence in the
organization's access-controlled incident or risk system. Do not commit
vulnerability details, customer exposure, exploit material, personal data,
credentials, or a completed acceptance record to this repository.

## Authority Boundary

A completed record may authorize only the temporary operation of the named
deployed systems under the named containment controls. It does not authorize a
merge, tag, signature, package upload, GitHub Release, TestPyPI publication,
PyPI publication, or an exception to any release gate. It cannot change the
support policy or make an unpublished correction available to customers.

Every correction still follows the single fail-closed publication path in the
[PyPI release runbook](release_pypi.md) and must pass
`make release-publish-check`. Operators must not disable, reclassify, waive, or
manually satisfy a failed gate to meet an incident deadline. The historical
security-maintenance diff checker is a review aid only and has no publication
authority.

## Intake Clock and Response Objectives

The normative intake policy is
`agent-assure/security-vulnerability-intake/v1`. Incident intake begins before
this risk-acceptance process is activated. Its clock starts at the earlier of an
external report's receipt and an internal detection, recorded respectively as
`report_received_at_utc` and `internally_detected_at_utc`. The derived
`clock_started_at_utc` must equal that earliest known instant. Forwarding,
validation, record creation, process activation, or reclassification cannot
change the start: those actions must not reset or pause the clock. If a report
credibly alleges a Critical trigger and the facts are incomplete, use Critical
objectives until a named incident owner records evidence supporting a lower
severity.

| Severity at receipt or detection | Primary page | Human acknowledgement | Initial severity and exposure assessment | Affected supported deployment response |
| --- | --- | --- | --- | --- |
| Critical | Immediate; confirm delivery within 5 elapsed minutes | Within 1 elapsed hour | Within 4 elapsed hours | Verified containment, verified no supported exposure, or safe-state entry within 4 elapsed hours |
| High | Immediate | Within 4 elapsed hours | Within 24 elapsed hours | Verified containment, verified no supported exposure, or safe-state entry within 24 elapsed hours |
| Medium or Low | Normal private intake | Within 3 business days | Within 7 business days | Track remediation and any required containment through normal governance |

Critical and High deadlines are continuous elapsed UTC time; nights, weekends,
and holidays do not pause them. These severity-specific objectives take
precedence over the general three- and seven-business-day targets in the public
security policy. A stricter organizational or legal SLA may take precedence only
when the incident record identifies its immutable policy ID and revision, scope,
owner, and precedence. An unreferenced private process cannot weaken these
objectives.

Private Vulnerability Reporting notifications must page the 24/7 primary
security on-call immediately. Confirm delivery within 5 elapsed minutes. A
delivery failure, reporting-service outage, or other primary-route outage pages
the independent fallback immediately through its separate route. Confirmed
delivery without a human acknowledgement within 15 elapsed minutes also pages
the fallback. The fallback must be a distinct person on duty and must not depend
solely on the same GitHub account, identity provider, or notification path.
Public documents name durable roles only; store personal details, schedules,
phone numbers, routing destinations, and escalation credentials in the
access-controlled incident system.

Within the applicable response objective, either verify effective containment,
record evidence that no supported deployment is affected, or enter every
potentially affected supported deployment into its documented safe state. A
missed objective, unavailable on-call role, failed route, or inability to bound
exposure is an incident control failure and triggers immediate escalation; it
never extends the objective or authorizes risk acceptance or publication.

## Activation and Severity

Open the process as soon as both conditions hold: a supported release has a
credible security exposure, and the correction cannot safely reach affected
operators through the standard gated release path within the required response
window. Containment may begin immediately under ordinary incident-response
authority; residual-risk acceptance becomes active only after all required
controls are implemented and independently approved.

Severity must reflect exploitability, exposed assets and data, privilege and
trust-boundary impact, deployment prevalence, existing controls, and credible
threat intelligence. A CVSS score can inform but must not determine severity by
itself. Record uncertainty explicitly; missing telemetry or an unknown exposure
population is not evidence of low risk.

| Severity | Trigger examples | Maximum acceptance window | Minimum reevaluation cadence |
| --- | --- | --- | --- |
| Critical | Active exploitation; signing or supply-chain compromise; broadly reachable code execution, authentication bypass, secret extraction, or destructive integrity loss | 24 hours | Every 4 hours |
| High | Credible exploitation with material confidentiality, integrity, or availability impact, but no confirmed critical condition | 72 hours | Every 24 hours |
| Medium | Material but bounded exposure for which verified containment cannot be kept solely in normal remediation tracking | 7 calendar days | Every 72 hours |
| Low | No emergency-risk acceptance | Use normal remediation and release governance | Per normal governance |

These are upper bounds, not service-level promises. Organizational or legal
policy may require shorter windows. A critical condition with no effective,
verifiable containment is not eligible for acceptance: disable, isolate, or
suspend the affected capability and escalate immediately. Suspected compromise
of release credentials, signing identity, workflow authority, or artifact
integrity also freezes publication until the standard trust chain is restored
and verified.

## Roles and Independence

Every active record names real people and durable organizational identities,
not only teams or aliases:

- The **Critical intake primary on-call** owns continuous initial receipt,
  paging, acknowledgement, and handoff. Its private route is tested and recorded
  in the incident system.
- The **Critical intake independent fallback on-call** is a different person on
  duty and has a durable route that does not rely solely on the primary route's
  GitHub account, identity provider, or notification path. It is paged on route
  failure, Private Vulnerability Reporting outage, or primary no-ack at 15
  elapsed minutes.
- The **accountable incident owner** owns the decision, affected-system scope,
  remediation path, deadlines, and closure. This person proposes but cannot
  approve the acceptance.
- The **independent security risk approver** is a different person with
  formally delegated authority to accept security risk. They must not be the
  correction author, release authorizer, accountable incident owner, or the
  sole validator of the compensating controls. Critical acceptance requires
  the CISO, equivalent executive, or a documented delegate authorized for
  critical risk.
- Each **control owner** implements and maintains one or more containment
  controls. Control effectiveness must be verified by someone other than the
  person who implemented that control.
- The **monitoring owner** owns detection coverage, on-call routing, alert
  testing, and evidence capture for the entire acceptance window.
- The **customer/advisory owner** coordinates affected-user guidance, upstream
  or downstream notifications, CNA/CVE activity when applicable, and legal,
  privacy, and regulatory review.

The accountable owner and independent approver must use distinct human
identities and record the approver's delegation reference. `CODEOWNERS`, a pull
request approval, or control of a release environment does not by itself prove
independent risk-acceptance authority. If no eligible independent approver is
available, risk acceptance is invalid and the affected capability must remain
disabled, isolated, or otherwise placed in a safe state.

## Containment Before Acceptance

Containment reduces exposure while the unpublished correction completes the
normal release process. Prefer controls that remove reachability or capability
over controls that merely detect exploitation. Applicable measures can include
disabling the vulnerable feature, revoking and rotating credentials, blocking
network paths, narrowing identities and permissions, quarantining affected
artifacts, pinning a known-safe version, restricting untrusted input, or moving
the workload behind an independently enforced policy boundary.

Each control entry must record its exact scope, owner, implementation time,
verification method, verifier, evidence reference and digest, expected failure
signal, rollback or safe-state action, and current status. A planned control is
not an implemented control. A control without recent effectiveness evidence
cannot support activation. Containment must cover every affected system in the
accepted scope; anything outside that scope is disabled, isolated, remediated,
or explicitly escalated.

Defense-in-depth controls must not be collapsed into one assertion. For
example, an ingress block, credential rotation, and alert rule are three
separate controls with separate owners and verification evidence. Record
dependencies and common-mode failure, including whether one administrator,
identity provider, network plane, or telemetry pipeline can defeat multiple
controls at once.

## Approval and Expiry

Before activation, the accountable owner signs the residual-risk statement and
the independent security risk approver records an explicit approve or reject
decision. The approval binds the incident ID, affected versions and systems,
correction identifier, implemented controls, monitoring plan, customer plan,
approval time, expiry time, and evidence snapshot. Approval of a mutable link
without a captured digest or immutable revision is insufficient.

The acceptance starts no earlier than the latest control-verification time and
expires automatically at the recorded UTC timestamp. It may not be open-ended,
backdated, or silently extended. Renewal requires a new decision and signature
over fresh evidence before expiry, with the prior record retained and linked.
Renewal cannot exceed the severity-specific maximum window and cannot be used
to normalize a recurring gate failure; repeated renewal escalates to the CISO
or equivalent executive and the affected business owner.

An expired, rejected, revoked, incomplete, or unsigned record authorizes
nothing. At expiry the operator must have published the correction through the
standard path, disabled or isolated the affected capability, or activated a
separately approved successor record. Expiry never makes a publication action
permissible.

## Monitoring and Reevaluation

The monitoring plan must cover attempted exploitation, unexpected access,
control health, configuration drift, telemetry loss, affected-version
inventory, and the status of the standard correction path. For every signal,
record its source, query or detector revision, alert threshold, owner, on-call
destination, response objective, retention location, and a successful test
with timestamped evidence.

Reevaluate at least at the severity cadence and after every material change.
Each review appends the current exposure, control status, monitoring results,
new threat intelligence, release-gate status, customer impact, and a decision
to continue, narrow, revoke, or close. Do not overwrite earlier reviews.

Immediately revoke and escalate the acceptance if exploitation is detected or
becomes materially more likely, an affected-system boundary expands, a control
or monitoring signal fails, evidence integrity is lost, the accountable owner
or approver changes, legal or regulatory duties change, or the residual-risk
assumptions no longer hold. Loss of observability is a control failure, not a
clean monitoring result.

## Customer and Advisory Coordination

The record must name the populations, customers, integrators, suppliers, and
downstream artifacts that may be affected. Coordinate privately with upstream
maintainers, a CNA, cloud or model providers, and relevant authorities when
applicable. Preserve embargo boundaries without using confidentiality to delay
protective action.

For each audience, record the owner, decision, rationale, channel, target time,
actual time, and approved content reference. Guidance should distinguish known
facts from uncertainty, identify affected and known-safe versions, describe
available containment, state correction availability honestly, and provide a
route for incident reports. Legal, privacy, contractual, and regulatory review
is required whenever data exposure, reporting duties, safety impact, or
coordinated disclosure may apply. A decision not to notify is itself a named,
approved, time-stamped decision; silence is not a default communication plan.

## Escalation and Safe Failure

Escalate immediately to the independent security approver and affected business
owner when a trigger for revocation occurs, the standard release is delayed
beyond the current window, customer scope grows, or a critical dependency
cannot be verified. Notify legal, privacy, compliance, executive leadership,
law enforcement, insurers, or regulators according to organizational policy
and jurisdictional obligations.

When there is disagreement, missing authority, incomplete evidence, missed
review, expired approval, or uncertainty about whether the controls are still
effective, fail closed: treat the acceptance as inactive and move the affected
capability to its documented safe state. Operational pressure, sunk cost, or a
ready correction does not supply missing authority.

## Evidence and Audit Record

Create the record from the checked-in template and retain it in an
access-controlled, append-only or equivalently auditable system. Preserve at
least the following:

- incident and risk-record IDs, confidentiality marking, intake-SLA policy ID
  and revision, severity basis, every receipt, detection, derived deadline,
  page, acknowledgement, assessment, containment, safe-state, breach, and
  escalation UTC timestamp, and immutable audit-log location;
- supported release, affected artifact digests, repository commit, correction
  identifier, failed release gates, and the current standard-release status;
- affected systems, tenants or customer cohorts, data classes, privileges,
  network boundaries, known exploitation, assumptions, and explicit unknowns;
- each compensating control and independent verification result;
- monitoring definitions, alert tests, observations, and on-call actions;
- accountable-owner attestation, independent approval decision, delegation
  evidence, signatures or approval-event references, and expiry;
- customer, supplier, advisory, legal, privacy, and regulatory decisions;
- immutable reevaluation entries, revocations, renewals, and closure evidence.

Use stable record IDs and content digests where the system supports them.
Access must follow least privilege, and audit logs must show creation, review,
approval, modification, access, revocation, and closure. The public repository
may receive a sanitized closure note only after disclosure review; the private
system remains the authoritative incident record.

To bind a final record without a recursive self-digest, export the approved
record once as an immutable byte artifact and compute SHA-256 over those exact
bytes. Store the digest only in a separate append-only audit event together
with the record ID, export reference, media type, byte length, algorithm, and
event timestamp. The immutable exported record contains its preassigned export
reference and metadata plus
`record_snapshot_digest_stored_outside_record: true`, but neither its own
digest nor an identifier for the later audit event. After export, the new audit
event binds those record fields to the computed digest in one direction; the
record never points forward to that event. Verification retrieves and hashes
the exact exported bytes; it must not parse, normalize, or reserialize them. The
`supporting_evidence_snapshot_sha256` field covers the separate supporting
evidence snapshot, not the risk-acceptance record.

## Closure

Close the record only after the correction has passed the standard publication
path and affected deployments are verified on a corrected or known-safe
version, or after the affected capability has been permanently retired. Record
the release or retirement evidence, customer follow-through, credential and
configuration cleanup, monitoring outcome, disclosure status, remaining risk,
and lessons learned.

Closure does not delete the acceptance history. Retain it according to the
organization's security, legal, contractual, and privacy retention schedule.
Create tracked follow-up actions for control gaps, release-gate latency,
telemetry failures, or recurrence, each with an owner and due date.

## Operator Checklist

1. Capture the earliest report-receipt or internal-detection time, start the
   continuous UTC clock, page the severity-appropriate route, and do not put
   exploit details in the repository.
2. For Critical intake, confirm primary delivery within 5 elapsed minutes and
   page the independent fallback on route failure, reporting-service outage, or
   no human acknowledgement at 15 elapsed minutes.
3. Open a restricted incident, assign severity, and derive each response
   deadline from the original intake clock; uncertainty does not lower a
   credible Critical signal.
4. Name the accountable owner, independent security approver, control owners,
   monitoring owner, customer/advisory owner, and the primary and fallback
   on-call roles.
5. Bound the affected systems and customer population; record unknowns.
6. Implement and independently verify containment or enter the affected scope's
   documented safe state before the applicable objective expires.
7. Test monitoring and the documented safe-state action.
8. Complete the template, capture immutable evidence, and obtain distinct
   owner and approver attestations with an explicit UTC expiry.
9. Coordinate customer, upstream, CNA/CVE, legal, privacy, and regulatory work
   as applicable.
10. Reevaluate on schedule and on every trigger; revoke on control or telemetry
   failure.
11. Publish only after the unchanged standard release gates pass.
12. Close with deployment, communication, audit, and lessons-learned evidence.
