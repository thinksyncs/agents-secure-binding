# AGTP Feedback Scope

This file is a non-normative, human-facing feedback checklist. The normative
source of truth for the profile is `docs/SSOT.md`.

The purpose of this file is to keep only the AGTP-facing feedback that is worth
human review and likely implementation work. Detailed protocol mechanics,
generic token behavior, and editorial preferences belong elsewhere unless they
change what implementations must reject.

AGTP core is treated as existing work in the
[Agent2Agent GitHub repository](https://github.com/a2aproject/A2A) and as one
reference target for this profile. This repository should not define a
competing AGTP core protocol or an AGTP subset. The intended contribution is
narrower:

- a security profile that can be applied to AGTP and similar deployments;
- implementation feedback from the
  [Cocos](https://github.com/ultravioletrs/cocos) hardware-attested TLS
  identity-policy work;
- interop and negative test vectors for security-sensitive behavior.

## Selection Rule

Keep an item here only when missing it can cause one of these acceptance
failures:

- a binding from the wrong live TLS or attestation session is accepted;
- the right platform is accepted for the wrong service, tenant, agent, task, or
  authority boundary;
- replay, stale state, missing state, or required-mode downgrade is accepted;
- peer-selected metadata becomes verifier policy.

Omit items that are mainly:

- AGTP message syntax that belongs to the core AGTP draft;
- AGTP transport selection;
- agent discovery semantics;
- generic OAuth, OIDC, JWT, JWS, CWT, or COSE behavior;
- editorial naming or explanatory wording without a security test impact.

## High-Priority Feedback

Feedback to the AGTP draft should be framed as security-profile requirements and
test-vector requests, not as a new core protocol.

| ID | Human review question | Required profile decision | Test-vector anchor |
| --- | --- | --- | --- |
| AGTP-FB-01 | How is AGTP-carried identity material bound to the accepted TLS and attestation session? | A Session Binding Statement must be verifiable against the accepted endpoint key, exporter context, attestation binder when present, and replay state. Mismatches fail closed. | `hwtls-id-profile-relay-001`; future attestation-binder mismatch vector |
| AGTP-FB-02 | Which semantic target values are verifier-local policy, and which are only observed peer claims? | Service, tenant, deployment, agent or workload, task or delegation, scope, resource, and authorization values must be compared against local expected policy. Peer-provided values must not become expected values. | `hwtls-id-profile-diversion-001`; `hwtls-id-profile-wrong-agent-001`; `hwtls-id-profile-binding-confusion-001` |
| AGTP-FB-03 | Which freshness values are one-shot, and what happens when replay state is unavailable? | Required freshness checks must use fail-closed replay state. A repeated Session Binding Statement identifier, nonce, or task-binding value is rejected. | `hwtls-id-profile-replay-001` |
| AGTP-FB-04 | What happens in required mode when grant or binding material is missing, unsupported, substituted, or only partially verified? | Required mode fails closed. A Manager-signed Identity Grant authorizes upper-layer semantics; an Agent-signed Session Binding Statement binds that grant to the accepted session. Neither statement alone is sufficient. | `hwtls-id-profile-downgrade-001`; future nested-token substitution vector |

AGTP may carry identity and policy material, but it must not make
peer-controlled metadata authoritative.

Binding means receiver-verifiable linkage, not necessarily embedding a TLS
session identifier in the statement.
