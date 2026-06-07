# AGTP Security Profile Feedback Scope

This note fixes the scope for the independent AGTP/aTLS follow-up work.

The AGTP core protocol is treated as existing work in the Agent2Agent
Internet-Draft stream. This repository should not define a competing AGTP core
protocol. The intended contribution is narrower:

- a security profile for using aTLS with AGTP;
- implementation feedback from the Cocos aTLS identity-policy work;
- interop and negative test vectors for security-sensitive behavior.

## In Scope

The profile and feedback work should focus on the failure classes that were
useful in the Cocos review:

- relay and borrowed-evidence resistance;
- diversion resistance through intended deployment identity checks;
- same-machine wrong-agent resistance through workload or agent identity checks;
- replay resistance for task and session binding;
- binding-parameter confusion, especially verifier-controlled labels,
  contexts, grants, confirmation keys, and policy inputs.

## Out of Scope

The follow-up work should not redefine:

- AGTP message syntax that belongs to the core AGTP draft;
- AGTP transport selection;
- agent discovery semantics;
- generic OAuth, OIDC, JWT, JWS, CWT, or COSE behavior;
- a complete Cocos replacement platform.

## Feedback Shape

Feedback to the AGTP draft should be framed as security-profile requirements
and test-vector requests, not as a new core protocol:

1. Which values must be locally expected by the verifier?
2. Which values may be carried by AGTP messages?
3. Which values must be signed by a Manager or policy authority?
4. Which values must be bound to the accepted aTLS session?
5. Which replay cache or nonce semantics are required?
6. Which negative test vectors should every implementation reject?

The central rule is simple: AGTP may carry identity and policy material, but it
must not make peer-controlled metadata authoritative.
