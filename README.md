# AGTP aTLS Profile

This repository explores an aTLS-backed security profile for AGTP.

The goal is to make AGTP deployments easier to review for relay resistance,
diversion resistance, same-machine wrong-agent confusion, replay resistance, and
binding-parameter confusion.

This repository does not define the AGTP core protocol. It is intended as a
companion security profile, implementation-feedback workspace, and test-vector
set for existing AGTP work.

## Focus

- aTLS session binding for AGTP profile data
- Manager-signed identity grants
- Session Binding Statements tied to the accepted aTLS session
- local expected-value checks for deployment, agent, task, and capability
- negative test vectors for relay, diversion, wrong-agent, replay, downgrade,
  stale evidence, measurement mismatch, and binding-parameter confusion

## Non-Goals

- redefining AGTP core messages
- replacing AGTP transport choices
- replacing Cocos
- defining a complete OAuth or OIDC profile
- inventing new cryptography

## Repository Layout

- `docs/architecture.md`: security-profile architecture and role split
- `docs/threat-model.md`: relay, diversion, wrong-agent, replay, and downgrade
  threat model
- `docs/agtp-atls-binding-profile.md`: aTLS binding expectations for AGTP
- `docs/agtp-security-profile-mapping.md`: profile validation state machine and
  error mapping
- `docs/agtp-security-profile-feedback.md`: draft-feedback scope and boundaries
- `interop/testvectors/`: positive and negative security-profile vectors
- `pkg/agtp/`: AGTP identity grant and session-binding helpers
- `pkg/atls/identitypolicy/`: local expected-value policy checks

## Test Vectors

The initial test-vector set is in `interop/testvectors/vectors.jsonl`.

It covers:

- baseline acceptance
- relay or borrowed-evidence rejection
- diversion rejection
- same-machine wrong-agent rejection
- replay rejection
- binding-parameter confusion rejection
- downgrade rejection
- stale-evidence rejection
- measurement-mismatch rejection
- policy-denied rejection

The vectors are profile-level vectors. They do not define AGTP core syntax.

## Relationship to Cocos

This repository started from Cocos aTLS implementation experience. Cocos is
treated here as related implementation experience and as a source of concrete
security-profile requirements.

This repository does not replace Cocos and should not be read as a Cocos fork
continuation.

## Relationship to AGTP

AGTP core is treated as existing draft work. This repository explores security
checks and test vectors that can be proposed as implementation guidance or draft
feedback.

The central rule is simple: AGTP may carry identity and policy material, but it
must not make peer-controlled metadata authoritative.

## Verification

For the current local implementation checks:

```sh
go test ./pkg/agtp ./pkg/atls/identitypolicy
go test ./pkg/clients ./pkg/clients/http ./pkg/clients/grpc
```

Some client tests open local loopback listeners. In restricted sandboxes, those
tests may need to run outside the sandbox.

## License

This repository currently keeps the original Apache-2.0 license.
