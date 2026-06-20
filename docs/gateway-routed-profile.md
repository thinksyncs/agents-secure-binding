# Gateway-Routed Profile

This document is a future profile sketch, not part of the v0.3 core
direct-Agent profile. In gateway-routed mode, the gateway terminates the TLS
session and performs the hardware-aware profile checks. The gateway is the live
TLS endpoint. Gateway session binding proves the gateway endpoint, not the
final Agent process.

The v0.3 runtime client path implements direct-Agent mode. A gateway-routed
deployment needs a separate route assertion before the relying party can treat
the final Agent as accepted.

## Route Assertion

A gateway route assertion is signed by a gateway route-signing key. That key
must be authorized by local verifier policy, a trusted gateway registry, or the
Manager-signed Identity Grant. It must not be inferred merely from the
client-to-gateway TLS endpoint key. The gateway route-signing key is a separate
key use from Manager signing keys and Agent confirmation keys.

The gateway route assertion states what the gateway observed and what it
guarantees. The JSON claim names are fixed by this profile:

| Claim | Required | Meaning |
| --- | --- | --- |
| `gta_type` | yes | Fixed string `ai2ai.gateway-route-assertion`. |
| `gta_version` | yes | Integer profile version, currently `1`. |
| `iss` | yes | Gateway issuer identity. |
| protected `kid` | yes | Gateway route-signing key ID in the protected JWS or COSE header. |
| `aud` | yes | Relying-party audience. |
| `jti` | yes | Unique route assertion ID. |
| `iat` | yes | Assertion issued-at time. |
| `exp` | yes | Short assertion expiry. |
| `nonce` | yes | One-shot replay nonce for this route assertion. |
| `grant_hash` | yes | Hash of the exact verified Identity Grant bytes. |
| `gateway_session_binding_sha256` | yes | Hash of the gateway Session Binding Statement or accepted gateway session-binding object. |
| `route_id` | yes | Canonical gateway route ID. |
| `next_hop` | yes | Canonical selected upstream endpoint or workload route. |
| `tenant` | conditional | Tenant or authority partition when the gateway is multi-tenant or policy-partitioned. |
| `principal` | conditional | Principal or caller partition when local policy distinguishes principals. |
| `authority_scope` | conditional | Authority-scope partition when delegation or policy is scoped. |
| `policy_id` | yes | Canonical policy ID or policy-version reference used for route selection. |
| `target_agent` | yes | Canonical final Agent ID. |
| `target_workload` | conditional | Final workload identity when distinct from `target_agent`. |
| `target_agent_key_thumbprint` | conditional | Expected final Agent confirmation-key thumbprint when holder-of-key proof is required. |
| `upstream_authn` | yes | Upstream authentication method observed by the gateway, such as `mtls`, `spiffe`, `service-mesh`, or `agent-hok`. |
| `upstream_peer` | yes | Canonical upstream peer identity observed by the gateway. |
| `request_context_sha256` | yes | Hash of the same canonical request context used for the routed authentication instance. |
| `task_id` | conditional | Canonical task ID when task-scoped. |
| `context_id` | conditional | Canonical context ID when context-scoped. |
| `session_id` | conditional | Canonical application session ID when session-scoped. |
| `audit_hash` | conditional | Hash over deployment-defined audit material for later correlation without trusting logs as policy. |
| `agent_hok_proof_sha256` | conditional | Hash of the gateway-to-Agent holder-of-key proof when required. |

The same claim names are used in JWT/JWS. The JWS protected header `typ`
SHOULD be `ai2ai+gateway-route+jwt`. For CWT/COSE, the text claim names above
are encoded in canonical CBOR unless a deployment profile assigns fixed private
numeric labels and publishes test vectors for the mapping. The COSE `kid` used
for key lookup must be protected.

All identifier values are canonical before signing. The verifier MUST NOT
normalize peer-provided aliases during acceptance. Missing, ambiguous, or
unsupported canonicalization fails closed.

mTLS, SPIFFE/SPIRE, service-mesh identity, and workload identity can be inputs
to the gateway's observation. They do not by themselves become relying-party
acceptance evidence unless the gateway signs the route assertion and the
verifier checks it against local policy. The gateway must map those inputs to
canonical Agent and workload identifiers before signing.

An Agent-side holder-of-key proof is required unless local policy explicitly
trusts the gateway as the delegation authority for the final Agent process. When
required, the gateway route assertion carries the Agent proof hash or key
thumbprint, and the verifier rejects the route if the proof is absent, expired,
replayed, signed by the wrong key, or not tied to the same `grant_hash`, route,
tenant partition, and request context.

## Replay and Partitioning

Gateway replay handling is separate from direct-Agent Session Binding Statement
replay handling. The replay cache key for gateway route assertions includes at
least:

```text
iss || aud || tenant || authority_scope || route_id || grant_hash || nonce
```

Multi-tenant gateways must partition route assertions, replay state, response
caches, and key caches by tenant or equivalent authority boundary. A route
assertion accepted for one tenant, principal, authority scope, route, Agent, or
task must not be reused for another.

## Failure Semantics

Failure semantics are fail-closed. The verifier rejects missing route
assertions, stale route assertions, unknown or disabled gateway route keys,
wrong tenant partitions, stale gateway registries, route-policy mismatches,
unavailable replay state, missing Agent holder-of-key proof when required, and
gateway assertions that only prove the gateway endpoint.

If the gateway route signing key or gateway policy authority is compromised,
this profile cannot recover the true final Agent identity. The deployment must
rely on gateway key revocation, route-policy rollback, audit, and isolation
controls.
