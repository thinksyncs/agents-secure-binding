# AGTP Security-Profile Mapping

This document maps the security-profile checks onto existing AGTP work. It does
not define AGTP core syntax.

## Profile Inputs

The profile needs four categories of input:

- lower aTLS binding facts from the accepted session;
- Manager-signed Identity Grant;
- confirmation-key-signed Session Binding Statement;
- local expected policy values.

Only the first three may be carried or referenced by AGTP messages. Local
expected policy values come from verifier configuration, Manager state, task
state, or a policy engine.

## Validation State Machine

```text
START
  -> ATLS_ACCEPTED
  -> GRANT_VERIFIED
  -> SESSION_BINDING_VERIFIED
  -> REPLAY_CHECKED
  -> LOCAL_POLICY_CHECKED
  -> PROFILE_ACCEPTED
```

Any failure moves to `PROFILE_REJECTED`.

## Validation Sketches

Relay and borrowed evidence:

```text
if session_binding.accepted_key != atls.accepted_key: reject
if session_binding.exporter_context != atls.exporter_context: reject
if replay_cache.seen(session_binding.id): reject
```

Diversion:

```text
if policy.requires_service and grant.service != policy.service: reject
if policy.requires_tenant and grant.tenant != policy.tenant: reject
if policy.requires_deployment and grant.deployment != policy.deployment: reject
```

Wrong-agent:

```text
if policy.requires_agent and grant.agent != policy.agent: reject
if session_binding.signer_key != grant.confirmation_key: reject
```

Replay:

```text
if grant.expired or session_binding.expired: reject
if replay_cache.unavailable and profile_requires_replay_cache: reject
if !replay_cache.set_once(session_binding.id, ttl): reject
```

Binding-parameter confusion:

```text
if token.type != locally_supported_type: reject
if token.version != locally_supported_version: reject
if token.alg not in locally_allowed_algorithms: reject
if observed_value used as expected_value: reject
```

## Error Mapping

Profile implementations should return stable error classes:

| Error class | Meaning |
| --- | --- |
| `profile_required` | profile material was required but absent |
| `grant_invalid` | Identity Grant verification failed |
| `session_binding_invalid` | Session Binding Statement verification failed |
| `replay_detected` | nonce, grant id, or binding id was reused |
| `policy_mismatch` | observed values did not match local expected policy |
| `unsupported_profile` | token type, version, or algorithm was unsupported |
| `binding_parameter_confusion` | local expected values were missing or peer-controlled |

## Draft Feedback Questions

Useful feedback for the existing AGTP draft:

1. Where should profile material be carried or referenced?
2. Which profile fields should be mandatory for attested deployments?
3. Which error classes should be visible to the peer?
4. Which failures should be audit-only versus fail-closed?
5. Which test vectors should be shared across implementations?
