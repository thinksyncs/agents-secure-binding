# Application-Profile Security Mapping

Security-profile checks map onto application-profile material. AGTP is one
reference target and one useful feedback path, but the profile does not define
AGTP core syntax.

## Profile Inputs

The profile needs four categories of input:

- lower TLS and post-handshake hardware-attestation binding facts from the
  accepted session;
- Manager-signed Identity Grant;
- confirmation-key-signed Session Binding Statement;
- local expected policy values.

Only the first three may be carried or referenced by application-protocol
messages. Local expected policy values come from verifier configuration,
Manager state, task state, or a policy engine.

Canonical semantic-reference rules are defined in
`docs/SSOT.md`. This mapping assumes
decision-sensitive references are already canonical before verification.
Receivers compare those values deterministically and reject peer-provided
aliases, fuzzy matches, or non-canonical values.

## Validation State Machine

```text
START
  -> TLS_ACCEPTED
  -> HARDWARE_PROFILE_ACCEPTED
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
if peer_alias used as normalized_reference: reject
if fuzzy_match used for authorization: reject
```

Reference normalization:

```text
if policy.requires_intent_ref and grant.intent_ref != policy.intent_ref: reject
if policy.requires_capability_ref and grant.capability_ref != policy.capability_ref: reject
if policy.requires_ontology_id and grant.ontology_id != policy.ontology_id: reject
if alias_resolution_missing_or_ambiguous: reject
if receiver_canonicalizes_peer_value_on_acceptance: reject
if free_form_text used as decision_authority: reject
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
| `ambiguous_reference` | alias or semantic reference normalization was missing or ambiguous |

## Draft Feedback Questions

Useful AGTP feedback questions:

1. Where should profile material be carried or referenced?
2. Which profile fields should be mandatory for attested deployments?
3. Which error classes should be visible to the peer?
4. Which failures should be audit-only versus fail-closed?
5. Which test vectors should be shared across implementations?
