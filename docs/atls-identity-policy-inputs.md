# aTLS Identity Policy Inputs

This note tracks identity inputs that are outside the basic TLS channel-binding
mechanism. It is a design note, not a production bug claim.

The current aTLS implementation can be reviewed in layers. The lower layers are
transport and attestation binding checks. The upper layers are deployment and
agent policy checks.

- L1: attestation or authenticator material is bound to the accepted TLS
  session.
- L2a: the attested platform or VM measurement is appraised.
- L2b: the attested platform is checked against the intended service, tenant,
  deployment, or environment.
- L3: the accepted platform is checked against the intended workload, process,
  or agent.
- L4: the accepted request or response is checked against the intended task,
  thread, context, or delegation.
- L5: the accepted action is checked against the intended authorization or
  capability policy.

L1 and L2a can be tested directly with implementation regressions. L2b through
L5 need explicit policy inputs before the verifier or application layer can
enforce them consistently.

OIDC and OAuth are useful reference patterns for these upper layers. They are
not required by this note. The important idea is that the verifier should compare
peer claims against locally expected values, rather than treating peer-supplied
values as the policy.

## Scope

This note does not change the aTLS verifier. It records the policy inputs that
would be needed before L2b through L5 can be enforced consistently.

Out of scope for this note:

- selecting a specific identity provider,
- defining a new token format,
- changing the attestation evidence format,
- changing the aTLS wire protocol,
- and proving an end-to-end authorization model.

## OIDC and OAuth-style mapping

OIDC and OAuth provide a useful vocabulary for local expected values:

| Layer | Policy question | OIDC / OAuth-style analogue |
| --- | --- | --- |
| L2b | Is this the intended service, tenant, deployment, or environment? | issuer, audience, tenant, hosted domain, deployment claim, environment claim |
| L3 | Is this the intended workload, process, or agent? | subject, client ID, workload identity, actor claim, confirmation key |
| L4 | Is this the intended task, thread, context, or delegation? | nonce, state, transaction ID, request object, delegation token |
| L5 | Is this action authorized for this peer and context? | scope, resource indicator, authorization details, policy decision, consent |

These names are analogies, not normative requirements. A CoCos deployment could
source the same expected values from configuration, a registry, CoRIM metadata,
an EAT claim, an agent manifest, or an application policy engine.

## L2b: intended service, tenant, or deployment

The verifier needs a local source of expected identity values. Examples include:

- service identity,
- tenant identity,
- deployment or environment identity,
- region or location, if relevant,
- CoRIM or evidence fields that represent these values,
- and the local policy source for the expected values.

The key question is whether a valid platform measurement is also tied to the
intended service or deployment subject.

## L3: intended workload, process, or agent

Machine-level attestation may not be enough when several workloads or agents run
on the same platform. The verifier or application layer may need expected values
such as:

- workload ID,
- agent ID,
- process or binary hash,
- config or policy hash,
- agent public key,
- and routing target or ingress identity.

The key question is whether the accepted peer is the intended workload or agent,
not only a workload on a valid attested machine.

## L4: intended task, thread, context, or delegation

An accepted peer can still be used in the wrong application context. The
application layer may need expected values such as:

- computation ID,
- task ID,
- thread or conversation ID,
- request context,
- delegation token,
- callback or ingress binding,
- and locally tracked one-shot state.

The key question is whether the accepted response is tied to the task or
delegation that the relying party intended.

## L5: authorization or capability policy

Identity alone does not decide whether an action is allowed. The policy layer
may need expected values such as:

- OAuth scope or authorization detail,
- capability token,
- resource indicator,
- user consent record,
- policy-engine decision,
- and tool or data-access policy.

The key question is whether the accepted peer is authorized for the requested
action in the current context.

## Possible CoCos input sources

The table below lists candidate input sources. It is intentionally descriptive;
it does not claim that all inputs already exist or are enforced today.

| Layer | Candidate local expected value | Possible CoCos source |
| --- | --- | --- |
| L2b | Expected service, tenant, deployment, or environment | manager configuration, deployment registry, CoRIM metadata, EAT claim, operator policy |
| L3 | Expected workload, process, or agent | agent manifest, workload ID, binary or config hash, agent public key, ingress routing policy |
| L4 | Expected task, thread, context, or delegation | computation ID, request context, session state, delegation token, callback binding |
| L5 | Expected authorization or capability | OAuth/OIDC-style policy, capability token, policy engine, user consent, tool policy |

## Fail-closed principle

For L2b through L5, the safe default should be fail closed when an expected local
value is required but unavailable, ambiguous, or only peer supplied.

Concrete policy rules should follow this shape:

- The expected value comes from local configuration, a trusted registry, an
  attestation policy, or a policy engine.
- The received claim is compared against that local expected value.
- Missing expected values do not silently relax the check.
- Peer-provided values are never promoted into expected values without a trusted
  policy decision.
- A mismatch is a hard failure for flows that require that layer.

## Suggested next step

Document which L2b through L5 inputs CoCos deployments expect to enforce. After
that, add minimal fail-closed checks for missing or mismatched expected values at
the layer where enforcement belongs.
