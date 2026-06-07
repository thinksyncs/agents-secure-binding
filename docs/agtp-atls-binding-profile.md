# AGTP aTLS Binding Profile

This document describes the aTLS binding expectations for an AGTP security
profile. It does not introduce new cryptography.

## Binding Goal

The relying party should accept AGTP profile material only when it is tied to
the same accepted aTLS session and to locally expected identity policy.

The profile separates two questions:

- L2 relay defense: is the profile material bound to this accepted aTLS
  session?
- L3 and above: is the accepted session the intended deployment, agent, task, or
  authorized actor?

## Exporter Label and Context

Implementations should use locally expected exporter labels and contexts.

Rules:

- the verifier must not adopt a peer-supplied exporter label as the expected
  label;
- unsupported labels fail closed;
- context values must be fresh enough for the profile's replay window;
- context values used for task or grant binding must be compared with local
  expected state.

## Evidence and Authenticator Freshness

Profile deployments should define:

- evidence lifetime;
- grant lifetime;
- session-binding statement lifetime;
- maximum clock skew;
- replay-cache TTL.

Recommended starting point:

| Value | Starting policy |
| --- | --- |
| Identity Grant lifetime | short-lived, deployment-defined |
| Session Binding Statement lifetime | very short-lived, session-scoped |
| Replay cache TTL | at least the binding statement lifetime plus clock skew |
| Clock skew | explicit, small, and locally configured |

## Binding Statement Requirements

A Session Binding Statement should include:

- profile type;
- profile version;
- grant hash;
- accepted aTLS key or key fingerprint;
- accepted exporter context or equivalent session-binding value;
- nonce or binding id;
- expiry;
- issuer or signer key id.

The signer must be the confirmation key named by the verified Identity Grant, or
another key explicitly authorized by local policy.

## Failure Semantics

The profile fails closed when:

- a required Identity Grant is absent;
- a required Session Binding Statement is absent;
- grant and binding statement do not match;
- the replay cache is unavailable;
- evidence or profile material is stale;
- local expected policy cannot be loaded;
- labels, contexts, token types, versions, or signing methods are unsupported.

## Privacy Limits

Binding values should not reveal more identity information than needed. The
profile should prefer scoped grants, short lifetimes, minimal audit fields, and
audience-restricted tokens.

## Feedback Boundary

If existing AGTP syntax already has a place for profile material, this profile
should use it. If not, the feedback to AGTP should request only the smallest
profile extension needed to carry or reference the security-profile material.
