# Security Red-Team Test Notes

These notes describe the live-style red-team regressions for the AGTP identity
hook used by hardware-aware TLS clients.

For the current coverage report and LRTT backlog, see
`docs/live-red-team-report.md`.

## Scope

Most tests exercise the production-facing client hook:

- `AttestedClientConfig.AGTPObservedIdentity()`
- `agtp.VerifySessionIdentityJWT`
- `identitypolicy.ValidateAssertion`
- `identitypolicy.MemoryReplayCache`

The CWT/COSE profile tests exercise `agtp.VerifySessionIdentityCWT` directly,
because runtime client configuration is still JWT/JWS-wired. The client-hook
tests confirm that attacker-shaped inputs are rejected through the same callback
that a client configuration wires into the lower-layer TLS and attestation
acceptance path.

## Tests

The client-hook red-team coverage lives in `pkg/clients/clients_test.go`. The
CWT/COSE profile red-team coverage lives in `pkg/agtp/cwt_test.go`.

### `TestAGTPObservedIdentityAcceptsManagerIssuedGrantE2E`

This test uses small in-process issuer helpers to model the intended flow:

- a Manager issues an Identity Grant;
- an Agent issues a Session Binding Statement for that exact grant;
- the client verifies both through `AGTPObservedIdentity()`;
- the resulting assertion is compared with the accepted TLS session binding.

This keeps the test close to the production client hook without requiring a
network Manager service.

### `TestAGTPObservedIdentityRedTeamRealTLSAttestationBinding`

This test uses an in-memory TLS 1.3 connection and the exported-authenticator
attestation path before calling the AGTP client hook.

It checks:

- a Manager grant and Agent Session Binding Statement are accepted when their
  binding values come from the same real TLS exporter and accepted attestation
  payload;
- a Session Binding Statement whose binding values were borrowed from another
  TLS / attestation session is rejected with `identitypolicy.ErrMismatch`.

This is still a dependency-free CI test. It does not generate hardware evidence
inside a confidential VM.

### `TestVerifySessionIdentityCWTRedTeamRejectsCOSEProfileAttacks`

This test signs AGTP Identity Grants and Session Binding Statements as
CWT/COSE_Sign1 tokens and verifies that the binary encoding profile enforces
the same trust model as JWT/JWS.

It checks:

- an Agent-signed forged grant and a tampered Manager-key signature are
  rejected;
- a Session Binding Statement signed by an otherwise valid but unauthorized
  binding key is rejected;
- a binding statement cannot target a different Manager-signed grant hash;
- an expired binding statement is rejected;
- a grant that passes signature checks still fails local policy comparison when
  its semantic identity values drift;
- a COSE `kid` in the unprotected header is rejected.

This test does not change the trust model. CWT/COSE changes the encoding and
signature container; issuer trust, confirmation-key authority, exact grant hash,
freshness, replay, and local policy comparison remain the acceptance gates.

### `TestAGTPObservedIdentityAcceptsHTTPJWKSAndRejectsRevocation`

This test uses `httptest` to model external key and revocation sources:

- `/jwks` returns Manager and Agent verification keys;
- `/revocations` returns revoked grant `jti` values;
- the client uses a `KeyFunc` backed by the HTTP key source;
- the client rejects a grant when the HTTP revocation source lists its `jti`.

This is not a Redis, JWKS, or registry product implementation. It is a
dependency-free integration test showing how the existing verification hooks
fail closed when caller-supplied HTTP key and revocation sources are wired in.

### `TestAGTPObservedIdentityRedTeamRejectsAttacks`

This test builds Manager-signed Identity Grants and Agent-signed Session
Binding Statements, then mutates them into attacker-shaped cases.

It checks:

- a peer-signed grant cannot impersonate the Manager;
- a diverted service identity cannot satisfy local client policy;
- diverted tenant or deployment identity cannot satisfy local client policy;
- a borrowed binding for a different accepted leaf key is rejected.
- a borrowed binding for a different request context is rejected.

These cases cover the main intended failure classes for the AGTP identity hook:

- unauthorized issuer or signing key;
- diversion against local expected service, tenant, and deployment identity;
- relay or borrowed-evidence attempts against the accepted TLS endpoint key and
  request context.

### `TestAGTPObservedIdentityRedTeamRejectsAgentThreats`

This test exercises agent-specific semantic threats through the same live client
hook. It binds a valid Manager grant and Agent session-binding statement to
service, workload, task, delegation, scope, resource, and authorization policy,
then mutates one boundary at a time.

It checks:

- impersonation by a peer-signed grant;
- prompt-injection-shaped unsafe task context;
- tool misuse through the wrong tool scope;
- data exfiltration through the wrong resource target;
- capability escalation through a stronger-than-authorized scope;
- policy bypass through required mode without concrete checks;
- confused-deputy behavior through the wrong delegation id;
- a newly spawned agent key attempting to inherit a parent grant;
- audit evasion through missing grant or binding ids.

These cases treat identical machine, account, or session context as insufficient
unless the semantic agent, task, delegation, capability, and audit bindings also
match local policy.

### `TestAGTPObservedIdentityRedTeamRejectsReplay`

This test calls the same observed-identity callback twice with the same valid
Session Binding Statement and replay cache.

It checks:

- first use is accepted;
- second use is rejected with `identitypolicy.ErrReplayDetected`.

### `TestAGTPObservedIdentityRedTeamRejectsReplayRace`

This test submits the same valid Session Binding Statement concurrently through
one shared replay cache.

It checks:

- exactly one concurrent attempt is accepted;
- duplicate attempts fail with `identitypolicy.ErrReplayDetected`.

This is a single-process live-style race, not a multi-node distributed replay
test.

### `TestAGTPObservedIdentityRedTeamRejectsReplayRaceMultiProcess`

This test starts several local worker processes from the test binary. Each
worker builds the same Manager-signed Identity Grant, the same Agent-signed
Session Binding Statement, and the same accepted validation binding, then calls
`AGTPObservedIdentity()` against one shared HTTP SETNX-style replay service.

It checks:

- exactly one worker accepts the session binding;
- every duplicate worker fails with `identitypolicy.ErrReplayDetected`;
- replay protection is enforced across process boundaries, not only across
  goroutines in one address space.

The local replay service models SET NX EX semantics: record the
`grant_hash/audience/nonce` key once for the binding TTL, return duplicate on
subsequent attempts, and fail closed if the store cannot make that decision.
This is still a dependency-free local harness, not a live Redis, Valkey, or
multi-node deployment test.

### `TestAGTPObservedIdentityRedTeamRejectsKeyAndRevocationFailures`

This test exercises key and revocation failure modes through the client hook.

It checks:

- stale JWKS that lacks a rotated Manager key fails closed;
- key rotation overlap accepts a rotated Manager key only when the key source
  contains both the old and rotated keys;
- HTTP JWKS `500` fails closed;
- HTTP JWKS timeout fails closed;
- revocation-source outage fails closed before accepting the grant;
- a disabled Manager key rejects the Identity Grant;
- a revoked Manager grant `jti` is rejected;
- a disabled Agent binding key rejects the Session Binding Statement.

### `TestAGTPObservedIdentityRedTeamRejectsAttestationBinderMismatch`

This test starts from an accepted synthetic attestation binder and mutates only
the Session Binding Statement `attestation_binder_sha256` value.

It checks that a valid grant, leaf key, request context, and local policy are
not enough when the attestation binder differs from the accepted lower-layer
validation result.

### `TestAGTPObservedIdentityRedTeamRejectsGrantSubstitution`

This test signs two Manager grants and presents a Session Binding Statement that
hashes the wrong grant.

It checks that the verifier rejects grant substitution through the
`grant_hash` comparison even when both grants are Manager-signed.

### `TestVerifySessionIdentityJWTEnvelopeRedTeamRejectsSubstitution`

This test exercises the `pkg/agtp` single-envelope JWT/JWS verifier. The outer
envelope is signed by the Agent binding key and carries the exact inner
Manager-signed Identity Grant JWT plus the session-binding fields for that
grant.

It checks:

- replacing the inner grant without updating the outer `grant_hash` is rejected;
- an outer `grant_hash` that does not match the exact inner grant bytes is
  rejected;
- an Agent-signed inner grant cannot bypass Manager-signature verification;
- a tampered outer envelope cannot bypass Agent-signature verification;
- Agent-signed semantic claims in the outer envelope are ignored rather than
  treated as Manager authorization;
- an envelope without an inner grant is rejected.

This covers the nested or single-envelope substitution class without changing
the trust model. The runtime client configuration path remains wired to the
two-token JWT/JWS profile.

### `TestAGTPObservedIdentityRedTeamRejectsVerifiedGrantCacheMisuse`

This test accepts a grant once, then retries with a fresh Session Binding
Statement after the same grant `jti` is listed as revoked.

It checks that prior successful verification is not acceptance evidence for a
later session.

## Expected Result

All red-team cases should fail closed before the client treats the observed
identity as accepted. Successful execution means the attacker-shaped input was
rejected, not accepted.

## Command

Run the focused client red-team tests with:

```sh
env GOCACHE=/tmp/go-build-cocos go test -count=1 ./pkg/clients
```

For the broader security regression set, run:

```sh
env GOCACHE=/tmp/go-build-cocos go test -count=1 ./pkg/agtp ./pkg/atls/identitypolicy ./pkg/atls/ea ./pkg/atls/eaattestation ./pkg/atls/internal_transport ./pkg/atls ./pkg/clients ./pkg/clients/grpc ./pkg/clients/http
```
