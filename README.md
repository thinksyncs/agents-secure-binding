# Agents Secure Binding

This repository contains the implementation notes, tests, vectors, and
supporting documents for a core verifier-side acceptance profile for
session-bound Agent identity.

A verifier accepts an Agent only when a verified authority grant,
holder-of-key proof, accepted TLS or exported-authenticator session, freshness
and replay state, any required attestation result, and verifier-local policy
all describe the same intended interaction.

The profile is a verifier-side acceptance gate over existing mechanisms. It is
not a TLS extension, attestation evidence format, identity provider,
holder-side presentation format, registry, control plane, gateway, or
application protocol.

The repository engineering source for implementation-specific profile text,
tests, and derived notes remains `docs/SSOT.md`.

The profile makes relay, replay, token substitution, same-host wrong-Agent
confusion, peer-metadata injection, context diversion, confused-deputy
behavior, cache confusion, and gateway route confusion concrete. Application
protocols can carry the profile material, but they do not by themselves supply
the verifier-side acceptance rule.

## Why This Profile Exists

Automated agents often combine transport authentication, signed authorization
material, platform attestation, and local policy. Each component can verify
successfully while the composition still authenticates the wrong session, task,
platform, or Agent.

The core invariant is simple: a verifier must not return a
profile-authenticated Agent identity unless the verified grant, proof, accepted
session, freshness state, replay state, any required attestation result, and
local policy identify the same intended interaction.

## Specification Overview

This profile uses D0 through D6 as acceptance dimensions. These labels are for
policy separation and diagnostics. They are not OSI layers, wire-format layers,
or a trust hierarchy.

| Dimension | Verification target | Main failure class |
| --- | --- | --- |
| D0 | Live TLS or exported-authenticator session | MITM or session confusion |
| D1 | Attested platform validity, when required | Fake, malformed, stale, or untrusted evidence |
| D2 | Attestation or authenticator-to-session binding | Relay, replay, or borrowed evidence |
| D3 | Service, tenant, deployment, or environment | Wrong service or tenant; context diversion |
| D4 | Workload, process, or Agent | Same-host wrong-Agent confusion |
| D5 | Task, thread, context, or delegation | Wrong task or delegation; context diversion |
| D6 | Authorization or capability policy | Confused deputy or privilege escalation |

D0 through D2 are authentication and binding dimensions. D3 through D6 are
verifier-local policy dimensions. Peer-provided metadata can be observed input;
it is not expected policy.

The current Go identity-policy API focuses on D3 through D6 checks after the
lower-layer TLS and attestation binding checks have accepted the session.

### Binding Profiles

The core profile is not a complete wire-binding profile by itself. A binding
profile instantiates it for a protocol or deployment by fixing the exact wire
representation, canonicalization, exporter label, replay rules, diagnostic
behavior, and protocol-specific inputs.

A binding profile using this core profile needs to define at least:

- profile identifier and version
- `protocol_id`
- TLS exporter label
- canonical `aud` form
- exact bytes used for `grant_hash`
- session-proof encoding and protected-header rules
- `task_context` and request-context construction
- nonce generation, lifetime, and replay-key construction
- attestation requirement and session-binding rule
- verifier-local source of D3 through D6 expected values
- diagnostic error classes

### Reference-Value Normalization

Decision-sensitive values such as `intent_ref`, `capability_ref`, and
`ontology_id` must already be canonical before acceptance. Receivers compare
them deterministically and do not repair peer-provided aliases, display labels,
URI variants, natural-language phrases, or model interpretations in the final
acceptance path.

Canonical references also need a trusted registry namespace and version. The
same string from two registries, or from two registry versions, is not
automatically the same authority value.

## Risk Guide

The profile separates risks by the first acceptance dimension where binding is
missing, ambiguous, stale, or controlled by the peer.

In this guide, "wrong-context acceptance" covers cases where the channel,
session, token, or peer may be valid, but the action is bound to the wrong
service, tenant, Agent, task, delegation, capability, or authority boundary.

| Risk | Short description | Main dimensions | Expected profile response |
| --- | --- | --- | --- |
| Relay / borrowed evidence | Evidence or a binding proof from one endpoint is accepted on another live session. | D0-D2 | Reject if the proof does not match the accepted endpoint key, exporter context, request context, attestation binder when required, nonce, or replay state. |
| Replay | A previously valid grant or session proof is reused. | D2, D5 | Require freshness, expiry, one-shot values, and an atomic replay cache. Fail closed if replay state is unavailable. |
| Service / tenant diversion | The peer is genuine, but not the intended service, tenant, deployment, or environment. | D3 | Compare verified grant values with verifier-local expected policy. |
| Same-host wrong-Agent | The host or platform is acceptable, but the workload, process, or Agent is not. | D4 | Require Agent or workload identity and confirmation-key binding. |
| Cross-task / context diversion | The peer is correct, but the response is tied to the wrong task, thread, context, or delegation. | D5 | Bind task or delegation identifiers and reject mismatches or replays. |
| Confused deputy / over-authorization | The peer is correct, but the requested action is not authorized. | D6 | Check scopes, resources, authorization details, and local policy decisions. |
| Binding-parameter confusion | The verifier treats peer-provided labels, contexts, keys, grants, or expected values as local policy. | D2-D6 | Keep observed values separate from expected values. Fail closed on unsupported labels, token types, versions, algorithms, or canonicalization rules. |
| Stale trust state | A key, grant, registry entry, revocation state, evidence challenge, or local policy value is outdated. | D2-D6 | Enforce issuer, audience, key status, key use, revocation, evidence freshness, replay TTL, and local policy lifetime. |

## Focus

- verifier-side acceptance before returning a profile-authenticated Agent
  identity
- authority grants and holder-of-key session proofs
- TLS exporter, request-context, nonce, and replay checks
- optional attestation-to-session binding when required by local policy
- separate TLS endpoint, Agent binding, and policy-authority key roles
- local expected-value checks for service, tenant, Agent, task, and capability
- negative test vectors for relay, replay, wrong-context acceptance,
  wrong-Agent, downgrade, stale evidence, measurement mismatch, and
  binding-parameter confusion

## Evaluation Status

The v0.4 evaluation is useful but not sufficient proof of the full
security claim. It combines focused local checks, negative test vectors,
unit-level coverage, dependency-free live-style harnesses, a deterministic
acceptance-invariant matrix, and local gateway route-assertion tests. The
status is tracked in `docs/live-red-team-report.md`, including local TLS
resumption coverage, route-assertion wire-token adapters, and remaining real
0-RTT transport behavior, gRPC connection pooling, runtime gateway wiring, a
full gateway-routed network harness, randomized fuzz/property generation, and
hardware-generated confidential-VM attestation replay.

## Non-Goals

- defining a TLS extension
- defining a new attestation evidence format
- selecting an identity provider
- defining a universal Agent namespace
- defining a holder-side presentation format
- defining a registry, control plane, gateway, or application protocol
- defining a complete OAuth, OIDC, or authorization framework
- replacing AGTP, A2A, Cocos, TLS, or remote attestation standards
- inventing new cryptography

## Repository Layout

- `docs/SSOT.md`: repository engineering source for implementation-specific
  profile text, semantic-reference rules, and verification order
- `docs/architecture.md`: security-profile architecture and role split
- `docs/threat-model.md`: relay, diversion, wrong-agent, replay, and downgrade
  threat model
- `docs/hwtls-binding-profile.md`: TLS and attestation binding expectations
  for application profiles
- `docs/http-cache-profile.md`: non-normative HTTP response-cache profile for
  endpoints near identity-binding decisions
- `docs/gateway-routed-profile.md`: gateway route-assertion profile and
  final-Agent holder-of-key boundary
- `pkg/agtp/gatewayroute/`: local gateway route-assertion policy gate
- `docs/ai2ai-security-profile.md`: A2A/AGTP mapping, wallet boundary, and
  Security Binding Object carrier rules
- `docs/agtp-security-profile-mapping.md`: profile validation state machine and
  error mapping
- `docs/agtp-security-profile-feedback.md`: high-priority AGTP security-profile
  feedback
- `docs/live-red-team-report.md`: current live-style red-team coverage and LRTT
  backlog
- `docs/static-diversion-policy.md`: static service / tenant diversion policy
- `interop/testvectors/`: positive and negative security-profile vectors
- `pkg/agtp/`: AGTP identity grant and session-binding helpers
- `pkg/agtp/diversionpolicy/`: static diversion-policy evaluator
- `pkg/atls/identitypolicy/`: local expected-value policy checks

## Test Vectors

The initial test-vector set is in `interop/testvectors/vectors.jsonl`.
Static diversion-policy examples are in
`interop/testvectors/diversion-policy-examples.jsonl`.

It covers:

- baseline acceptance
- relay or borrowed-evidence rejection
- service / tenant diversion rejection
- same-machine wrong-agent rejection
- replay rejection
- binding-parameter confusion rejection
- downgrade rejection
- stale-evidence rejection
- measurement-mismatch rejection
- policy-denied rejection

The vectors are profile-level vectors. They do not define AGTP core syntax.

## Implementation Provenance

This work uses
[ultravioletrs/cocos](https://github.com/ultravioletrs/cocos) as related
implementation experience and as a source of concrete requirements. Cocos
itself is not the scope of this security profile.

## Reference Protocol Notes

A2A/AGTP-style protocols are possible mapping targets; see the
[Agent2Agent GitHub repository](https://github.com/a2aproject/A2A) and
[nomoticai/agtp](https://github.com/nomoticai/agtp). This repository stays at
the verifier acceptance, binding-profile, and test-vector layer. AGTP, A2A, or
any similar application protocol may carry identity and policy material, but it
does not by itself provide all of the TLS-exporter, request-context, replay,
attestation-to-session, canonical-reference, and local-policy checks needed
here. Peer-controlled metadata is never verifier-local expected policy.

## Verification

For the current local implementation checks:

```sh
go test ./pkg/agtp ./pkg/atls/identitypolicy
go test ./pkg/clients ./pkg/clients/http ./pkg/clients/grpc
```

Some client tests open local loopback listeners. In restricted sandboxes, those
tests may need to run outside the sandbox.

## Authorship and Review

This repository is maintained by ToppyMicroServices OÜ. Published
specifications, tests, and releases are reviewed and accepted by the
maintainer.

## License

This repository currently keeps the original Apache-2.0 license.
