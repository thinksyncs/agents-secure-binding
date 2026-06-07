# AGTP aTLS Security-Profile Architecture

This document sketches the architecture for an aTLS-backed security profile for
existing AGTP work. It does not define AGTP core messages.

## Roles

- Client: the relying party that accepts an AGTP peer only after aTLS and
  profile checks succeed.
- AGTP peer: the endpoint reached over the accepted aTLS session.
- Manager or policy authority: the local trust anchor that signs Identity
  Grants.
- Agent binding key: the confirmation key named by a verified grant and used
  to sign a Session Binding Statement.
- Verifier: the component that compares observed session-bound identity values
  against local expected policy.

## Layer Split

The profile keeps the lower aTLS facts separate from application policy.

| Layer | Responsibility | Primary failure class |
| --- | --- | --- |
| L0 | Authenticate the live TLS channel | MITM or session confusion |
| L1 | Appraise platform or VM evidence | fake or malformed platform evidence |
| L2 | Bind attestation or authenticator material to the accepted TLS session | relay, replay, borrowed evidence |
| L3 | Check intended service, tenant, deployment, or environment | diversion |
| L4 | Check intended workload, process, or agent | wrong-agent |
| L5 | Check task, thread, context, or delegation | cross-task replay or confusion |
| L6 | Check authorization or capability policy | confused deputy |

AGTP core may carry profile material, but it must not make peer-controlled
metadata authoritative. The verifier compares session-bound observed values
against local expected values.

## Profile Objects

Identity Grant:

- signed by a Manager or policy authority;
- names the intended deployment, agent, task, and capability values;
- names the confirmation key that may bind the grant to an aTLS session;
- has issuer, audience, expiry, issued-at time, and unique token id.

Session Binding Statement:

- signed by the confirmation key named by the verified grant;
- includes a hash of the verified Identity Grant;
- includes the accepted aTLS session binding values;
- includes a fresh nonce or replay-cache key;
- expires quickly.

Observed Identity Assertion:

- derived only after both objects verify;
- passed to local identity policy;
- rejected if required local expected values do not match.

## Data Flow

1. The client establishes the lower aTLS session.
2. The profile verifier extracts accepted aTLS binding facts.
3. The AGTP peer presents an Identity Grant and a Session Binding Statement.
4. The verifier authenticates both objects under local trust policy.
5. The verifier checks replay state.
6. The verifier derives an observed identity assertion.
7. Local identity policy compares observed values with expected values.
8. The AGTP session is accepted only if all required checks pass.

## Audit

Implementations should log security-profile decisions without logging secrets.
Useful fields include:

- profile version;
- grant issuer;
- grant id;
- session binding id;
- accepted key fingerprint;
- expected policy name or id;
- failure class;
- failure reason.

## Non-Goals

This architecture does not define AGTP transport behavior, generic OAuth/OIDC
behavior, discovery semantics, or a complete authorization system.
