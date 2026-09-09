## Help wanted: short, no-user-secret external CI pilot for unreleased Agent Assure 0.6.6

> Maintainer deployment blocker: do not post this issue while the pilot
> workflows contain the zero execution-source sentinel/refusal step. Create and
> validate source commit `S`, then publish a later trusted workflow/docs commit
> `W` that pins both workflows to `S`. Replace the revision placeholders below
> with those distinct commits before recruiting.

We are seeking one GitHub user who is not an Agent Assure maintainer to attempt
a prepared controls-mutation workflow in a fork they control. Target
participant effort is 10–15 minutes; CI runtime may be longer. No
participant-supplied model/provider API key, proprietary data, repository
secret, or maintainer access is needed. GitHub supplies its normal short-lived,
read-only workflow token. A blocked or failed attempt can still be useful when
its execution and friction evidence is complete.

The published GitHub/PyPI release is still `0.6.5`; this exercise targets exact
bytes from an unreleased `0.6.6` pre-candidate, not a published release or RC.

This is privacy-filtered onboarding-learning evidence only—not endorsement,
adoption, customer testimony, third-party validation, a safety/security
assessment, or exact-candidate release validation.

You should volunteer only if:

- you are not an `acblabs/agent-assure` maintainer;
- you control the fork and its Actions settings without `acblabs` operating
  the run;
- you will use the pinned GitHub-hosted runner, not a self-hosted runner;
- you can commit one benign, participant-authored non-bundled input;
- you can explicitly consent to a 14-day capture handoff in your public
  fork's Actions storage, accessible under GitHub's repository read-access
  rules and containing disclosed linkable pseudonymous bindings;
- you can inspect the result and report friction; and
- you can grant or decline prospective publication authorization for the
  documented outcome-dependent privacy-filtered inventory, including up to
  14 days of Stage 2 public-fork Actions storage and the disclosed random
  cross-stage correlation binding and public committed-input digest
  linkability.

Please read the
[external pilot quickstart](https://github.com/acblabs/agent-assure/blob/TRUSTED_WORKFLOW_REVISION/docs/external_pilot_quickstart.md).
The private handoff will name that immutable `TRUSTED_WORKFLOW_REVISION` for
workflow/documentation bytes and the distinct immutable
`EXECUTION_SOURCE_REVISION` embedded in the workflow for the wheel source.
Do not post credentials, private data, direct identities intended for the
evidence bundle, raw prompts/outputs, or confidential repository content.
Reply `interested` only. Do not post your fork or run URLs; a maintainer will
arrange a privacy-appropriate handoff. An issue reply expresses interest; it
is neither storage nor publication consent.
