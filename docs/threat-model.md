# AGTP aTLS Security-Profile Threat Model

This document records the threat model for an aTLS-backed AGTP security profile.
It is intended to guide implementation feedback and test vectors.

## Assumptions

- TLS 1.3 and exported-authenticator validation are implemented by the lower
  aTLS layer.
- Platform evidence appraisal is handled by the lower attestation verifier.
- The Manager or policy-authority signing key is configured locally or through
  a trusted key source.
- Peer-provided metadata is never treated as local policy.
- Replay prevention is enforced by a caller-provided cache or equivalent
  one-shot state.

## Relay

Relay is a lower-layer binding failure. The attacker tries to make the client
accept evidence, an authenticator, or a proof that belongs to a different live
session or endpoint.

Profile requirement:

- bind profile objects to the accepted aTLS session;
- reject mismatched binding values;
- reject reused binding identifiers or nonces.

## Diversion

Diversion is an intended-subject failure. The accepted peer may be genuine, but
it is not the intended service, tenant, deployment, or environment.

Profile requirement:

- carry deployment identity only in authenticated grants;
- compare observed deployment identity with local expected policy;
- fail closed on missing or mismatched required values.

## Same-Machine Wrong-Agent

Wrong-agent confusion occurs when the machine or VM is acceptable, but the
workload, process, or agent is not the intended one.

Profile requirement:

- bind the intended agent or workload identity in the Identity Grant;
- require a confirmation key authorized for that grant;
- compare the observed agent identity with local expected policy.

## Replay

Replay occurs when a previously valid grant or binding statement is reused
outside its intended session, task, or freshness window.

Profile requirement:

- require expiration and issued-at checks;
- require a unique grant id and binding id;
- use a replay cache or equivalent one-shot state;
- fail closed when replay state is unavailable.

## Binding-Parameter Confusion

Binding-parameter confusion occurs when a verifier uses peer-supplied values as
expected local values. Examples include labels, contexts, grant ids,
confirmation keys, expected agent ids, task ids, or authorization scopes.

Profile requirement:

- distinguish local expected values from observed values;
- reject unexpected labels, contexts, token types, versions, and signing
  methods;
- reject grants or binding statements that do not match local trust policy.

## Downgrade and Policy Failure

The profile must fail closed when:

- profile material is required but absent;
- only one of the grant or binding statement is present;
- the replay cache is required but unavailable;
- the token type or profile version is unsupported;
- local expected values cannot be loaded.

## Privacy

The profile should avoid unnecessary disclosure of deployment or agent identity.
Where possible, implementations should use short-lived grants, scoped audience
values, and minimal audit fields.
