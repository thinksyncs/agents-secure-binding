# SSOT: Hardware-Aware TLS Identity Binding Profile (Draft v0.1.0)

This draft defines identity inputs that sit above basic TLS channel binding.
It is a profile specification, not a production bug report or a final standard.

This file is the single normative source of truth for the profile in this
repository. Other documents are explanatory, historical, implementation notes,
or test reports; when they disagree with this file, update this file first and
then align the dependent document.

Hardware-aware TLS means ordinary TLS 1.3 plus post-handshake platform
attestation and session binding. Platform attestation does not replace the TLS
handshake and does not authenticate the platform before a TLS channel exists.
The older shorthand `aTLS` appears only for existing
[Cocos](https://github.com/ultravioletrs/cocos) implementation code paths,
package names, or historical terms.

The profile is organized in layers. The lower layers cover transport and
attestation binding. The upper layers cover deployment and agent policy.

- L0: the accepted peer is on the expected live TLS channel.
- L1: the attested platform or VM measurement is appraised.
- L2: attestation or authenticator material is bound to the accepted TLS
  session.
- L3: the attested platform is checked against the intended service, tenant,
  deployment, or environment.
- L4: the accepted platform is checked against the intended workload, process,
  or agent.
- L5: the accepted request or response is checked against the intended task,
  thread, context, or delegation.
- L6: the accepted action is checked against the intended authorization or
  capability policy.

L0 through L2 can be tested directly with transport, attestation, and
implementation regressions. L3 through L6 need explicit policy inputs before the
verifier or application layer can enforce them consistently.

The L0-L6 names are local to this profile and the Go identity-policy API. They
are not an IETF-defined taxonomy.

| Layer | Verification target | Main failure class |
| --- | --- | --- |
| L0 | Live TLS channel | MITM or session confusion |
| L1 | Attested platform validity | Fake, malformed, or untrusted platform evidence |
| L2 | Attestation-to-channel binding | Relay, replay, or borrowed evidence |
| L3 | Intended service, tenant, deployment, or environment | Service / tenant diversion |
| L4 | Intended workload, process, or agent | Same-machine wrong-agent |
| L5 | Task, thread, context, or delegation binding | Cross-task or context diversion |
| L6 | Authorization or capability binding | Confused deputy or privilege escalation |

OIDC and OAuth are useful reference patterns for these upper layers. They are
not required by this note. The important idea is that the verifier should compare
peer claims against locally expected values, rather than treating peer-supplied
values as the policy.

## Terminology and Status

This is a draft security profile for implementation review and possible future
Internet-Draft work. It is not an IETF consensus document.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14, RFC 2119 and RFC 8174,
when, and only when, they appear in all capitals, as shown here.

## Scope

L3 through L6 need explicit policy inputs before the verifier can enforce them
consistently. The client transport exposes an optional
`atls.ClientConfig.IdentityPolicy` hook for callers that already have a trusted
source for observed identity values.

Out of scope for this note:

- selecting a specific identity provider,
- standardizing a concrete wire-token format,
- changing the attestation evidence format,
- changing the lower-layer TLS or post-handshake attestation wire protocol,
- and proving an end-to-end authorization model.

## Relationship to Application Protocols and AGTP

This profile is application-protocol neutral at the lower layers. AGTP /
Agent2Agent is one reference target; see the
[Agent2Agent GitHub repository](https://github.com/a2aproject/A2A). AGTP can
carry or reference upper-layer identity and policy material after TLS has
established the live channel and the post-handshake hardware-attestation gate
has verified the attestation and session-binding facts.

In this split, TLS and the hardware-aware profile keep responsibility for L0
through L2:

- L0: the live TLS channel is authenticated.
- L1: the attested platform or VM evidence is appraised.
- L2: the authenticator or attestation material is bound to the accepted TLS
  session.

An application profile, including an AGTP profile, can then carry or reference
the upper-layer identity and policy material needed for L3 through L6:

- L3: intended service, tenant, deployment, or environment.
- L4: intended workload, process, or agent.
- L5: intended task, thread, context, or delegation.
- L6: authorization or capability policy.

This keeps relay defense and diversion defense separate. Relay defense remains
a session-binding question at L2. Diversion and wrong-agent prevention
need an application profile to compare session-bound identity
claims with local expected policy at L3 and L4. Task and capability checks then
continue at L5 and L6.

When AGTP is used with this profile, peer-provided metadata is not
authoritative. AGTP can carry authenticated policy inputs, such as an Identity
Grant, and bind them to the accepted TLS session through a Session Binding
Statement. The verifier still compares observed values with local expected
values before accepting the peer as the intended deployment, agent, task, or
authorized actor.

One implementation profile used in this repository is:

```text
Identity Grant + hardware-aware TLS + OAuth/OIDC-style semantics + JWT/JWS encoding
```

OAuth and OIDC provide claim semantics and review vocabulary. JWT/JWS provides
the signed-token encoding. This keeps the relying party's L3 through L6
identity and authorization inputs compact and verifiable before they reach
`identitypolicy`.

The JWT/JWS profile is intentionally fail closed. The verifier uses locally
configured issuer, audience, signing-method, and key-lookup policy. Tokens must
carry the AGTP token type, AGTP profile version, expiration time, issued-at
time, and JWT ID. The signing-method allow-list must not include `none`.
Identity values carried in an Agent-provided token are not authoritative unless
the token verifies under a locally trusted Manager or policy-authority key.

This profile keeps three key roles separate:

- TLS endpoint key: proves possession for the accepted TLS or exported
  authenticator endpoint.
- Agent binding key: signs the Session Binding Statement that binds a verified
  grant to the accepted TLS session.
- Manager or policy-authority key: signs Identity Grants that authorize the
  intended deployment, agent, task, or capability values.

These keys may be related by deployment policy, but they must not be silently
treated as the same key. In particular, the Manager key is a token-signing or
policy-authority key, not a TLS endpoint key.

For same-machine wrong-agent resistance, Manager keys and Agent confirmation
keys are separate trust domains. Manager signing keys MUST NOT be accepted as
Agent confirmation keys. Agent confirmation keys MUST NOT be accepted as Manager
or policy-authority signing keys. A deployment may explicitly authorize an
endpoint key for session binding, but that authorization must come from the
verified grant or local policy; it must not be inferred from the TLS session
alone.

CWT/COSE is available as a compact binary encoding profile for the same
Identity Grant and Session Binding Statement model. The security rules stay the
same: the grant issuer must be trusted locally, the confirmation key must be
named by the verified grant, and the session-binding statement must bind that
exact grant to the accepted TLS session. The CWT profile uses standard CWT
registered claims for issuer, subject, audience, expiration, issued-at, and
token ID (`cti`), and it requires the COSE `kid` used for key lookup to be
protected.

### Key rotation and revocation

The JWT/JWS and CWT/COSE adapters verify token signatures against
caller-provided key lookup policy. They do not define how Manager keys are
rotated, how old keys are retired, or how grants are revoked before `exp`.

Deployments that use this profile should define:

- a trusted issuer namespace for Manager or policy-authority keys,
- key identifiers and key-version rules,
- overlap windows for key rotation,
- a revocation source for grants, Manager keys, or Agent binding keys when
  early invalidation is required,
- maximum grant and session-binding lifetimes,
- and replay-cache retention that is at least as long as the accepted
  session-binding lifetime.

Until those deployment rules exist, short grant lifetimes and fail-closed local
key lookup are the conservative default. A token signed with an unknown,
retired, or locally disabled key should be rejected.

Revocation has three separate targets:

- grant revocation rejects a specific Identity Grant by JWT `jti` or CWT `cti`;
- Manager-key revocation rejects grants signed by a disabled issuer key or
  `kid`;
- Agent binding-key revocation rejects Session Binding Statements signed by a
  compromised or retired confirmation key.

Unknown, revoked, or stale keys fail closed. A deployment that relies on JWKS or
another remote key set should define freshness, cache lifetime, and failure
handling for that key source.

### Initial production profile

The initial production profile is intentionally small. It is a local
implementation profile for fail-closed deployment behavior, not a new IETF
standard profile.

Production identity policy has two modes: disabled or required. In required
mode, the client must fail closed when any required policy input is missing,
untrusted, expired, replayed, or inconsistent with the accepted TLS session.
In particular, the client must not treat peer-provided metadata as expected
policy.

The required-mode profile has the following minimum requirements:

| Area | Requirement |
| --- | --- |
| Manager trust | Manager or policy-authority verification keys are configured locally by `kid`, algorithm, issuer, audience, and public key, or loaded through an equivalent fail-closed key source. |
| Key separation | Manager or policy-authority signing keys and Agent confirmation keys are separate trust domains. They MUST NOT be accepted interchangeably. |
| Grant lifetime | Identity Grants are short-lived and carry `iat`, `exp`, and a unique `jti`. |
| Grant revocation | A deployment can reject revoked grant `jti` values and disabled Manager-key `kid` values before `exp`. |
| Unknown keys | Unknown, disabled, retired, or stale `kid` values fail closed. |
| Session binding | Session Binding Statements are signed by the confirmation key named in the verified Identity Grant, or by another endpoint key explicitly authorized by that grant or local policy. |
| Session binding | Session Binding Statements carry the accepted TLS endpoint-key hash, request-context hash, and a one-shot nonce. When attestation is present, they should also carry the attestation-binder hash. |
| Replay | `AGTPObservedIdentity` requires a replay cache when AGTP identity tokens are configured. Single-process deployments may use `MemoryReplayCache`; multi-instance production deployments should use a shared replay cache with `SET NX EX`-style semantics. |
| Error handling | Failure to check keys, revocation, session binding, replay, or local identity policy is an authentication failure, not a warning. |

The initial JWT/JWS profile fixes the mandatory claim set below. A deployment
may add claims, but it must not remove these checks when identity policy is
required.

| Token | Mandatory claims |
| --- | --- |
| Identity Grant | `agtp_type`, `agtp_version`, `iss`, `aud`, `sub`, `jti`, `iat`, `exp`, `cnf.kid` |
| Session Binding Statement | `agtp_type`, `agtp_version`, `aud`, `jti`, `iat`, `exp`, `grant_hash`, `leaf_public_key_sha256`, `request_context_sha256`, `nonce` |

The profile keeps direct-Agent and gateway-terminated deployments separate:

- Direct-Agent profile: the Agent terminates the TLS session and performs the
  hardware-aware profile checks before signing the Session Binding Statement
  with the confirmation key named by the verified Identity Grant.
- Gateway-routed profile: the gateway terminates the TLS session and performs
  the hardware-aware profile checks. The deployment must also authenticate the
  gateway-to-Agent route before treating the intended Agent as accepted.
  Gateway session binding alone proves the gateway endpoint, not the final
  Agent process.

JWKS, DNS-AID, registry-based discovery, centralized revocation APIs, and
Redis-compatible replay stores can be added as production integrations. They do
not replace the local trust decision unless freshness, cache lifetime,
revocation behavior, and fail-closed handling are specified.

In implementation terms, AGTP can be introduced as a post-attestation profile
step before changing the lower-layer TLS or attestation wire protocol. The AGTP
step authenticates the grant, verifies the session binding statement against
the accepted TLS session, enforces replay policy, and then calls the same
`identitypolicy` validator used by the current Go API.

## Normalized reference values

Some L5 and L6 inputs are semantic references rather than raw labels. This
profile names three common examples:

- `ontologyId`: the stable identifier for the vocabulary or policy namespace
  used to interpret semantic references.
- `intentRef`: the stable identifier for the intended task, intent, or action
  family.
- `capabilityRef`: the stable identifier for an authorization capability or
  resource-action class.

These values are profile reference identifiers. They are not natural-language
prompts, display names, or peer-selected aliases.

Clients MUST NOT send free-form natural-language intent, context, or capability
text as decision-authoritative profile values. Free-form text MAY be sent as
descriptive metadata.

Decision-sensitive semantic values MUST be represented as canonical
identifiers. Receivers MUST validate those identifiers deterministically against
receiver-side policy, task state, trusted registry or profile data, signed
profile data, or the underlying interaction/security protocol.

Receivers MUST NOT normalize peer-provided decision-sensitive semantic values
during the final acceptance path. In particular, a receiver MUST NOT turn a
peer-provided alias, display label, natural-language phrase, case variant, or
URI variant into an accepted canonical identifier. The receiver compares
already-canonical identifiers against already-normalized expected values; if a
value is not canonical for the applicable profile or registry version, the
receiver rejects it.

Receivers MUST NOT use model-based or fuzzy semantic matching as the final
authority for authorization, routing, execution, task acceptance, or rejection.

### Client-side normalization obligation

The relying client, Manager, or local policy authority must resolve aliases and
produce normalized reference values before those values are used in an Identity
Grant, Session Binding Statement, local expected policy, or authorization
decision. The peer may present observed values, but it must not decide the
verifier's expected `intentRef`, `capabilityRef`, or `ontologyId`.

Normalization is therefore an issuance-time or local-policy operation, not a
receiver-side repair step for peer-provided decision values. A receiver may
validate syntax, profile version, and registry version, but it must not
canonicalize a non-canonical peer value into an accepted value.

Alias handling is part of local policy:

- an alias must resolve to exactly one normalized reference at the relevant
  registry or policy version;
- a missing alias, unsupported registry version, or ambiguous alias fails
  closed;
- case folding, Unicode normalization, URI normalization, or prefix expansion is
  allowed only when the referenced identifier scheme defines it;
- otherwise, normalized references are compared as exact strings;
- set-like fields, such as scopes, resources, and authorization details, use
  the configured set mode after normalization.

Verifier-side acceptance must not depend on fuzzy matching, prompt similarity,
model interpretation, or natural-language equivalence. If a deployment needs
human-readable labels, those labels should be carried as diagnostics or UI
metadata, not as authorization-critical reference values.

## OIDC and OAuth-style mapping

OIDC and OAuth provide a useful vocabulary for local expected values:

| Layer | Policy question | OIDC / OAuth-style analogue |
| --- | --- | --- |
| L3 | Is this the intended service, tenant, deployment, or environment? | issuer, audience, tenant, hosted domain, deployment claim, environment claim |
| L4 | Is this the intended workload, process, or agent? | subject, client ID, workload identity, actor claim, confirmation key |
| L5 | Is this the intended task, thread, context, or delegation? | nonce, state, transaction ID, request object, delegation token |
| L6 | Is this action authorized for this peer and context? | scope, resource indicator, authorization details, policy decision, consent |

These names are analogies, not normative requirements. A deployment could source
the same expected values from configuration, a registry, CoRIM metadata, an EAT
claim, an agent manifest, or an application policy engine.

## Policy shape

The core rule is to keep expected values separate from observed values, and to
bind observed values to the accepted TLS session.

- Expected values come from local policy, configuration, a trusted registry, or
  a policy engine.
- Observed values come from a session-bound identity assertion extracted from
  attestation evidence, CoRIM metadata, EAT claims, agent manifests,
  authenticated or locally derived request metadata, or authorization tokens.
- Verification compares observed values against expected values.
- Observed values must not become expected values without a trusted local policy
  decision.

A minimal policy object can be shaped as follows:

```yaml
identity_policy:
  mode: "disabled"
  set_mode: "contains_all"

  require:
    l3: false
    l4: false
    l5: false
    l6: false

  expected:
    service: ""
    tenant: ""
    deployment: ""
    environment: ""
    workload: ""
    agent: ""
    agent_public_key: ""
    computation_id: ""
    task_id: ""
    thread_id: ""
    delegation_id: ""
    intent_ref: ""
    capability_ref: ""
    ontology_id: ""
    scopes: []
    resources: []
    authorization_details: []
```

After external identity material has been authenticated, the verified internal
`identitypolicy.Assertion` can be shaped as follows:

```yaml
identity_assertion:
  issuer: "manager-or-policy-engine"

  values:
    service: "payment-agent"
    tenant: "tenant-a"
    deployment: "prod"
    environment: "asia-northeast1"
    workload: "settlement-worker"
    agent: "agent-a"
    agent_public_key: "sha256:..."
    computation_id: "cmp-..."
    task_id: "task-..."
    thread_id: "thread-..."
    delegation_id: "delegation-..."
    scopes:
      - "orders:read"
    resources:
      - "orders"
    authorization_details:
      - "settlement"

  binding:
    leaf_public_key_sha256: "..."
    request_context_sha256: "..."
    attestation_binder_sha256: "..."
    nonce: "..."
    issued_at: "..."
    expires_at: "..."
```

This assertion is not a wire format. It is a local representation used after the
caller has authenticated the external identity material. `Assertion.Issuer` is
informational to `identitypolicy.ValidateAssertion`; it is trusted only if the
`ObservedIdentity` implementation has already verified the corresponding grant
issuer and trust anchor. The binding fields are what make the assertion a relay
defense rather than a plain metadata check.

An implementation can split this object across existing configuration, manager
state, agent metadata, or an external policy engine. The important part is the
source of authority, not the concrete serialization format.

## Issuer model

`identitypolicy.Assertion` is not a wire token. It is a verified internal
representation returned by `atls.ClientConfig.ObservedIdentity`. Any wire token,
manifest, EAT claim, CoRIM metadata, authorization token, or gateway statement
must be authenticated before the callback returns an assertion.

A production deployment should separate authority from session possession:

- Identity Grant: signed or otherwise authenticated by the Manager or another
  configured policy authority.
- Session Binding Statement: signed by the agent confirmation key named in the
  verified Identity Grant. The accepted endpoint key may be used only when the
  verified grant or local attestation policy explicitly binds that endpoint key
  to the same agent identity.

The Agent is not the authority for service, tenant, deployment, task, scope, or
resource values. An Agent-signed session binding is a holder-of-key proof, not
an authority statement.

### Identity Grant

The Identity Grant authorizes the intended upper-layer subject. The initial
wire profile uses JWT/JWS and OAuth/OIDC-style claim names where they fit. Other
encodings, such as CWT/COSE or a signed manifest, can be added later if they
preserve the same authority and session-binding rules.

An Identity Grant should include the deployment-specific equivalent of:

- AGTP token type (`agtp_type=agtp.identity-grant`),
- AGTP profile version (`agtp_version=1`),
- issuer (`iss`),
- subject (`sub`),
- audience (`aud`),
- unique grant ID (`jti`),
- service, tenant, deployment, or environment,
- workload or agent identity,
- agent public key or confirmation key (`cnf.kid` in the initial JWT/JWS
  profile),
- computation ID, task ID, thread ID, or delegation ID when known,
- canonical intent, capability, or ontology reference when those references are
  decision-sensitive,
- scopes, resources, or authorization details when required,
- issuer key ID or key version when needed for key rotation,
- issued-at and expiration time (`iat`, `exp`),
- and a unique grant ID.

### Session Binding Statement

The Session Binding Statement does not authorize identity or capability values.
It only proves that the holder of the confirmation key named in the verified
grant bound that grant to the accepted TLS session. A generic accepted endpoint
key is not sufficient unless the verified grant or local attestation policy
explicitly binds that key to the same agent identity.

A Session Binding Statement should include:

- AGTP token type (`agtp_type=agtp.session-binding`),
- AGTP profile version (`agtp_version=1`),
- unique binding statement ID (`jti`),
- `grant_hash`,
- `leaf_public_key_sha256`,
- `request_context_sha256`,
- `attestation_binder_sha256` when attestation is present,
- `aud` or relying-service ID,
- statement type, protocol name, and version,
- nonce or unique binding ID,
- `iat` or issued-at time,
- and expiration time.

The grant hash should be computed over an unambiguous byte string, for example:

```text
SHA-256("agtp.identity-grant.jwt.v1" || NUL || exact-signed-grant-bytes)
SHA-256("agtp.identity-grant.cwt.v1" || NUL || exact-signed-grant-bytes)
```

If a JSON-based format is used, the deployment must avoid ambiguous
canonicalization. Hashing the exact signed bytes, or using canonical CBOR/COSE,
is safer than hashing a re-serialized JSON object.

The reusable JWT/JWS and CWT/COSE adapters in `pkg/agtp` follow this rule. They
verify the signed grant, compute the domain-separated hash over the exact signed
token bytes, and convert the result into `identitypolicy.VerifiedGrant`.

### Verification order

The overall verifier should perform the checks below. In the production client
wiring, the `ObservedIdentity` callback performs external authentication and
constructs the verified assertion, while `identitypolicy.ValidateAssertion`
compares the assertion with the accepted TLS session binding and local expected
policy.

1. Verify the Identity Grant under a trusted Manager or policy-authority key.
2. Check grant issuer, audience, expiration, grant ID, and required scope or
   resource fields.
3. Verify that the Session Binding Statement signature key matches the
   grant confirmation key, or another endpoint key explicitly authorized by the
   verified grant or local attestation policy.
4. Verify that the statement grant hash matches the verified Identity Grant.
5. Verify that the statement audience matches the relying service or client.
6. Reject arbitrary accepted endpoint keys that are not explicitly bound by the
   verified grant or local attestation policy to the same agent identity, even
   when the underlying TLS session is otherwise valid.
7. Compare the statement binding fields with the accepted TLS session.
8. Enforce replay policy for grant IDs, binding IDs, or nonces when one-shot use
   is required.
9. Construct `identitypolicy.Assertion` only from the verified grant and binding
   statement.
10. Call `identitypolicy.ValidateAssertion` to compare the verified assertion
   with local expected policy.

`identitypolicy.ValidateAssertion` intentionally remains a comparator and
binding freshness checker. It does not parse or verify wire tokens, signatures,
grant formats, key rotation, revocation, or replay caches. Those checks belong
to the component that implements `ObservedIdentity`.

### Gateway mode

If the Agent terminates the accepted TLS session directly, the Agent can sign
the Session Binding Statement over the accepted session binding values only when
the verified Identity Grant names that Agent key, or explicitly binds the
accepted endpoint key to the same agent identity.

If an ingress proxy or gateway terminates TLS, the trust model is different:
the gateway is the live TLS endpoint. In that mode, policy must explicitly trust
the gateway and bind the gateway-to-agent route. The deployment can model this
with gateway ID, gateway public key, allowed route, and agent route fields in
the Identity Grant or in a separate gateway routing assertion. Without that
extra routing assertion, a gateway-terminated session binding does not by itself
prove that the intended Agent process handled the request.

A gateway routing assertion must not be treated as an Agent authority statement.
It only authenticates the gateway's routing decision. The relying party still
needs an Identity Grant for the intended Agent and, when required, an Agent-side
holder-of-key proof for the gateway-to-agent hop.

## Production wiring

The production client hook is:

- `atls.ClientConfig.IdentityPolicy` for local expected values.
- `atls.ClientConfig.ObservedIdentity` for a session-bound observed identity
  assertion extracted from a trusted source.

The hook runs after exported-authenticator and attestation validation, but
before the accepted TLS connection is returned to the caller.

The expected values are owned by local policy. In practice, that means manager
configuration, operator configuration, a trusted registry, or an authorization
policy engine. Peer-provided values must not become expected values.

The observed assertion is extracted by the caller-supplied `ObservedIdentity`
callback. That callback should read from trusted evidence, CoRIM metadata, EAT
claims, agent manifests, authenticated or locally derived request metadata, or
authorization tokens. If an identity policy is enabled without an
observed-identity callback, the client fails closed.

The client computes the expected session binding from the accepted
exported authenticator: the leaf public key, the certificate request context,
and the attestation binder when attestation is present. The observed assertion
must carry matching binding values and a non-expired `expires_at` value before
its identity fields are compared with local policy.

This gives the profile two distinct defenses:

- relay defense: the observed identity assertion must be tied to this accepted
  TLS session at L2, not borrowed from another endpoint or connection.
- diversion defense: the session-bound observed identity must match locally
  expected deployment identity at L3. Workload, task, and authorization checks
  continue at L4 through L6.

## L3: intended service, tenant, or deployment

The verifier needs a local source of expected identity values. Examples include:

- service identity,
- tenant identity,
- deployment or environment identity,
- region or location, if relevant,
- CoRIM or evidence fields that represent these values,
- and the local policy source for the expected values.

The key question is whether a valid platform measurement is also tied to the
intended service or deployment subject.

## L4: intended workload, process, or agent

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

## L5: intended task, thread, context, or delegation

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

## L6: authorization or capability policy

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

## Possible input sources

The table below lists candidate input sources. It is intentionally descriptive;
it does not claim that all inputs already exist or are enforced today.

| Layer | Candidate local expected value | Possible source |
| --- | --- | --- |
| L3 | Expected service, tenant, deployment, or environment | manager configuration, deployment registry, CoRIM metadata, EAT claim, operator policy |
| L4 | Expected workload, process, or agent | agent manifest, workload ID, binary or config hash, agent public key, ingress routing policy |
| L5 | Expected task, thread, context, or delegation | computation ID, request context, session state, delegation token, callback binding |
| L6 | Expected authorization or capability | OAuth/OIDC-style policy, capability token, policy engine, user consent, tool policy |

## Validation algorithm

For each layer that is required by policy:

1. Load the local expected value for that layer.
2. Reject if the expected value is missing or ambiguous.
3. Extract the observed session-bound identity assertion from the trusted source.
4. Reject if the assertion is not bound to the accepted TLS session.
5. Reject if the assertion is expired or missing freshness metadata.
6. Extract the observed value from the assertion for that layer.
7. Reject if the observed value is missing.
8. Compare the observed value with the expected value.
9. Reject on mismatch.
10. Continue to the next required layer.

For set-like values such as scopes, resources, or authorization details, the
observed set must satisfy the local policy. The default `contains_all` mode
accepts an observed set only when it contains every locally required value.
The stricter `exact` mode also rejects extra observed values. A peer-provided
scope list is not enough by itself.

## Fail-closed principle

For L3 through L6, the safe default should be fail closed when an expected local
value is required but unavailable, ambiguous, or only peer supplied.

Concrete policy rules should follow this shape:

- The expected value comes from local configuration, a trusted registry, an
  attestation policy, or a policy engine.
- The received claim is compared against that local expected value.
- Missing expected values do not silently relax the check.
- Peer-provided values are never promoted into expected values without a trusted
  policy decision.

When a deployment wants strict authorization, it should set `set_mode: exact`.
That makes L6 fail closed if a verified grant carries extra scopes, resources,
or authorization details beyond the local expected set.
- A mismatch is a hard failure for flows that require that layer.

## Error handling

Validation failures should preserve the layer, field, and error class. Callers
can then distinguish local policy configuration errors from missing peer claims
or mismatched values.

For example:

- missing local expected value: configuration or policy setup problem
- missing observed value: peer evidence, metadata, or token did not carry the
  required claim
- mismatch: peer supplied a claim, but it did not match local policy

Aggregated validation errors should remain inspectable by layer and field so
callers can fail closed while still reporting actionable diagnostics.

The validator also rejects unsafe identity-policy values, including invalid
UTF-8, control characters such as CRLF, and HTML delimiter characters. It also
limits individual values to 1024 bytes and set-like fields to 128 values. This
protects log, header, and diagnostic paths from accepting values that could be
reused for injection or resource-exhaustion attacks. Validation errors
intentionally report only layer, field, and error class; they do not echo raw
peer values. Any HTTP or HTML presentation layer must still use normal output
escaping and CSRF protections at that layer.

## Minimal implementation path

A small implementation can be staged without changing the lower-layer TLS or
post-handshake attestation wire protocol:

1. Define a local policy input structure for L3 through L6 expected values.
2. Define extraction points for observed values.
3. Add fail-closed validators for exact-match string fields.
4. Add set-containment validation for scopes, resources, or authorization
   details.
5. Wire the validators at the application or manager layer before treating an
   accepted peer as the intended deployment, agent, task, or authorized
   actor.

The lower-layer verifier can remain focused on L0 through L2. L3 through L6
enforcement can live at the layer that has access to deployment policy, agent
metadata, computation state, and authorization decisions.

## Implementation status

The reusable validator lives in `pkg/atls/identitypolicy`. It implements the
expected-versus-observed comparison model and session-bound assertion validation
described above. The client transport calls it when
`atls.ClientConfig.IdentityPolicy` is enabled.

The same package also provides a helper for the post-authentication step:
`identitypolicy.NewAssertionFromSessionBinding` builds an internal `Assertion`
from an already-authenticated Identity Grant and an already-verified Session
Binding Statement. It does not parse wire tokens or verify signatures; it only
checks that the statement is tied to the grant, audience, allowed confirmation
key, and minimum session-binding fields before the assertion is compared with
the accepted TLS session. `identitypolicy.SessionBindingOptions` can also
attach a replay cache for one-shot binding nonces.

The client config supports both integration styles. Callers can provide a
custom `ObservedIdentity` callback, or they can pass a verified Identity Grant,
a verified Session Binding Statement, and an optional replay cache directly on
`atls.ClientConfig`. In both cases, the transport validates the resulting
assertion against the accepted TLS session before returning the connection. For
the direct grant/statement path, replay-cache marking happens only after the
session-binding and local policy comparison succeed.

`pkg/agtp` provides the first concrete wire-token adapter for that direct path.
It verifies AGTP Identity Grants and Session Binding Statements encoded as
JWT/JWS, using locally configured issuer, audience, signing methods, and key
lookup policy. The adapter does not choose the trusted Manager keys, rotate
keys, perform revocation, or define deployment policy. Those remain caller
responsibilities.

The initial JWT/JWS adapter treats the grant `cnf.kid` value as the authorized
session-binding signer key. The Session Binding Statement signer is taken from
the protected JWS `kid` header and is later checked by `identitypolicy` against
the verified grant. Thumbprint-based confirmation, such as `cnf.jkt`, can be
added later once the deployment defines how key thumbprints map to local
verification keys.

The adapter also rejects tokens with the wrong AGTP token type, unsupported
profile version, missing JWT ID, missing grant confirmation key, missing
session-binding grant hash, missing required session-binding fields, or an
unsafe signing-method allow-list. It does not perform key rotation,
revocation, or replay-cache storage; those remain deployment responsibilities.

For callers that want one fail-closed acceptance gate, `pkg/agtp` also exposes
`VerifySessionIdentityJWT`. That helper verifies the Manager-signed Identity
Grant, verifies the Session Binding Statement, checks that the binding signer is
authorized by the verified grant, compares the resulting assertion with local
expected `identitypolicy.Policy` values and the accepted TLS session binding,
and only then marks the binding nonce in the replay cache. This prevents a peer
from making OAuth/OIDC-style claims authoritative by self-signing or simply
presenting them as metadata.

Callers are expected to:

- build a local `Policy` from trusted deployment or authorization inputs,
- extract or provide a verified observed identity assertion from the appropriate
  implementation layer,
- call `identitypolicy.ValidateAssertion`, provide the assertion through
  `atls.ClientConfig.ObservedIdentity`, or configure the verified grant and
  session-binding fields on `atls.ClientConfig`,
- and treat validation errors as fail-closed for layers required by policy.

`identitypolicy.Validate` reports all layer and field failures found in one
pass. Callers can inspect `ValidationErrors` for per-field diagnostics, while
still using `errors.Is` with the package sentinel errors.

## Implemented production profile

The initial production profile now has a fail-closed implementation path for
AGTP JWT/JWS identity material. `AGTPObservedIdentity` requires both an Identity
Grant and a Session Binding Statement, verifies them with locally configured
JWT policy, and requires a replay cache before accepting AGTP identity tokens.

The implemented profile covers:

- trusted Manager or policy-authority key lookup for Identity Grants through
  `JWTVerifyOptions`;
- issuer, audience, signing-method, `kid`, expiration, issued-at, token type,
  profile version, and `jti` checks;
- confirmation-key binding through the Identity Grant `cnf.kid`;
- Session Binding Statement signer authorization against the verified grant;
- comparison with the accepted TLS endpoint key, request context, and optional
  attestation binder;
- local `identitypolicy.Policy` comparison for required L3 through L6 values;
- and replay-cache enforcement before the observed identity is accepted.

Deployment still chooses the source of trusted keys, expected policy values,
revocation data, and distributed replay storage. Those sources can be manager
configuration, agent metadata, computation state, an authorization policy
engine, or a fail-closed registry integration. They must not be raw
peer-controlled metadata.

## Appendix: Identity Grant JWT claim map

The initial JWT/JWS profile uses two signed JWTs for different authority
questions:

- Identity Grant JWT: a Manager or policy authority signs the upper-layer
  identity, task, and authorization values that the peer is allowed to claim.
- Session Binding Statement JWT: the Agent confirmation key signs a
  holder-of-key statement that binds the verified grant to the accepted TLS
  session.

The Session Binding Statement JWT does not authorize service, tenant, task,
scope, resource, or capability values. Those semantic values belong in the
Identity Grant JWT and are accepted only after local policy comparison.

### Separation from Session Binding Statement JWT

A deployment may package the Manager-signed Identity Grant JWT inside, or
alongside, the Agent-signed Session Binding Statement JWT so an implementation
passes around one envelope. That packaging does not merge the authorities. The
verifier still has to validate the Manager or policy-authority signature on the
grant, validate the Agent confirmation-key signature on the session binding,
check that the session binding names the exact verified grant, and then compare
the resulting assertion with local policy.

Moving the semantic grant fields directly into an Agent-signed Session Binding
Statement would make the Agent the authority for service, tenant, task, scope,
resource, and capability claims. That changes the trust model and is unsafe for
profiles that need Manager- or policy-authority-issued authorization. A single
Manager-signed JWT that also includes session-binding values is possible only
when the Manager participates in, or is given trustworthy evidence of, the
per-connection TLS binding. That design adds an online authority dependency and
moves replay and freshness responsibilities to the Manager path.

The two-JWT design adds one additional JWS verification plus a domain-separated
hash over the exact compact Identity Grant JWT bytes. This is usually small
compared with TLS setup and attestation verification. Verifiers MUST NOT cache
a verified Identity Grant as acceptance evidence across sessions. If an
implementation performs internal optimization, it must still re-check the
Manager or policy-authority signature, expiration, revocation state, profile
version, issuer, audience, grant hash, fresh Session Binding Statement, replay
state, and local policy for each accepted session. A nested or single-envelope
transport only removes message plumbing; it does not remove the need for both
authority checks unless the trust model changes.

The reusable `pkg/agtp` JWT/JWS adapter also supports a single-envelope
verification path. In that profile, the outer envelope is signed by the Agent
binding key and carries the exact inner Manager-signed Identity Grant JWT plus
the session-binding fields. The verifier still authenticates the inner Manager
grant, authenticates the outer Agent binding statement, compares the outer
`grant_hash` with the exact inner grant bytes, enforces replay and freshness,
and compares the resulting assertion with local policy. Agent-signed semantic
claims in the outer envelope are not Manager authorization. The current runtime
client configuration remains wired to the two-token JWT/JWS profile unless a
caller explicitly uses the envelope verifier.

| Identity Grant JWT field | Source or form | Purpose | Layer |
| --- | --- | --- | --- |
| JWS protected header `kid` | Manager or policy-authority signing key ID | Select the local verification key for the signed grant. The value is only a key-selection hint; the signature still has to verify under local trust policy. | L0-L2 prerequisite |
| `agtp_type` | `agtp.identity-grant` | Distinguish the grant token from other AGTP profile tokens. | Profile guard |
| `agtp_version` | `1` | Reject unsupported wire-profile versions before interpreting claims. | Profile guard |
| `iss` | trusted Manager or policy authority | Identify the authority that issued the grant. | L0-L2 prerequisite |
| `aud` | relying service or application profile audience | Ensure the grant was issued for this verifier or application profile. | L0-L2 prerequisite |
| `sub` | upper-layer subject, usually the Agent when `agent` is absent | Provide the subject authorized by the grant. The adapter uses it as `agent` when no explicit `agent` claim is present. | L4 |
| `jti` | unique grant ID | Support grant uniqueness, revocation, diagnostics, and replay-sensitive handling. | Freshness prerequisite |
| `iat` | issued-at time | Detect future-issued or malformed grants and support freshness decisions. | Freshness prerequisite |
| `exp` | expiration time | Bound the lifetime of the authority statement. | Freshness prerequisite |
| `cnf.kid` | Agent confirmation key ID | Name the key allowed to sign the Session Binding Statement for this grant. | L4 and session-binding prerequisite |
| `authorized_endpoint_keys` | optional endpoint key IDs | Allow explicitly named endpoint keys when the deployment uses that binding model. | L4 and session-binding prerequisite |
| `service` | application service name or ID | Bind the grant to the intended service. | L3 |
| `tenant` | tenant or account ID | Bind the grant to the intended tenant. | L3 |
| `deployment` | deployment, region, cluster, or environment slice | Bind the grant to the intended deployment target. | L3 |
| `environment` | production, staging, development, or similar | Bind the grant to the intended environment class. | L3 |
| `workload` | workload, process, or component ID | Bind the grant to the intended workload. | L4 |
| `agent` | Agent identity | Bind the grant to the intended Agent rather than any peer on the same platform. | L4 |
| `agent_public_key` | stable Agent public-key reference or fingerprint | Bind the Agent identity to a specific key when required by policy. | L4 |
| `computation_id` | computation or job ID | Bind the grant to a computation instance. | L5 |
| `task_id` | task ID | Bind the grant to the intended task. | L5 |
| `thread_id` | thread, conversation, or workflow ID | Bind the grant to the intended thread or workflow context. | L5 |
| `delegation_id` | delegation token or delegation record ID | Bind the grant to a specific delegation chain or authorization handoff. | L5 |
| `intent_ref` | stable intent reference | Bind the grant to a canonical task or intent family rather than free-form text. | L5 |
| `capability_ref` | stable capability reference | Bind the grant to a canonical capability or resource-action class. | L6 |
| `ontology_id` | stable policy vocabulary or namespace ID | Identify the vocabulary used to interpret semantic references. | L6 |
| `scope` / `scopes` | OAuth-style scope values | State coarse authorization strings that local policy can require or compare exactly. | L6 |
| `resource` / `resources` | resource indicators or resource URIs | State the resources the grant may be used against. | L6 |
| `authorization_details` | profile-specific authorization detail strings | Carry finer-grained authorization purpose or constraint values, such as `purpose:monthly-settlement`, for local policy comparison. | L6 |
