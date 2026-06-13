# Security-Profile Test Scenarios

These scenarios are the minimum set that should exist before draft text is
written. They keep the feedback concrete.

## Positive Baseline

The grant is signed by the trusted Manager. The Session Binding Statement is
signed by the grant confirmation key. The binding statement matches the accepted
TLS session key and exporter context. Local expected service, tenant,
deployment, agent, task, and capability values match.

Expected result: accept.

## Relay or Borrowed Evidence

The grant is valid, but the Session Binding Statement names a different
accepted TLS key or exporter context than the accepted session.

Expected result: reject with `session_binding_invalid`.

## Service / Tenant Diversion

The grant is valid and session-bound, but its service, tenant, deployment, or
environment differs from local expected policy.

Expected result: reject with `policy_mismatch`.

## Static Diversion Policy

A static diversion policy is used when a deployment intentionally allows or
denies a service, tenant, deployment, environment, or agent target change. The
policy is local or policy-authority controlled, not peer-controlled.

Expected results:

- allowed client-visible diversion with notice: accept;
- hidden diversion without an explicit hidden rule: reject;
- wrong diverted target: reject;
- denied rule: reject with audit fields preserved.

## Same-Machine Wrong-Agent

The deployment identity matches, but the agent or workload identity differs
from local expected policy.

Expected result: reject with `policy_mismatch`.

## Replay

The grant and binding statement are otherwise valid, but the binding id or grant
id is already present in replay state.

Expected result: reject with `replay_detected`.

## Binding-Parameter Confusion

The peer supplies a label, context, token type, profile version, or expected
identity value that the verifier would need to adopt as policy for the session
to pass.

Expected result: reject with `binding_parameter_confusion`.

## Downgrade

Profile material is required, but either the Identity Grant or the Session
Binding Statement is absent.

Expected result: reject with `profile_required`.

## Stale Evidence

The grant or binding statement is expired.

Expected result: reject with `grant_invalid` or `session_binding_invalid`.

## Measurement Mismatch

The accepted TLS session has post-handshake attestation evidence, but the
appraised platform or VM measurement does not match local expected policy.

Expected result: reject with `policy_mismatch`.

## Policy Denied

The grant is valid and session-bound, but local policy requires a capability
that the grant does not contain.

Expected result: reject with `policy_mismatch`.
