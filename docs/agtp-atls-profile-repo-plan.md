# AGTP aTLS Profile Repository Plan

This note records the initial scope for a future repository that is independent
from the Cocos fork.

## Repository Name

Recommended name:

```text
agtp-atls-profile
```

The name is intentionally narrow. It says that the repository is an aTLS-backed
security profile for AGTP, not a replacement for AGTP core and not a complete
Cocos platform fork.

## Scope Statement

The repository should focus on:

- an aTLS security profile for existing AGTP work;
- implementation feedback from the Cocos aTLS identity-policy experience;
- test vectors for relay, diversion, wrong-agent, replay, and
  binding-parameter confusion;
- Internet-Draft material that can be offered as feedback to the existing AGTP
  draft stream.

The repository should not define:

- a competing AGTP core protocol;
- a new agent discovery model;
- a general authorization framework;
- a full Cocos replacement platform;
- new cryptographic primitives.

## Related-Work Wording

Suggested wording for Cocos:

> The Cocos aTLS work is treated as implementation experience and as a source
> of concrete security-profile requirements. This profile does not replace
> Cocos or claim to be a Cocos fork.

Suggested wording for AGTP:

> AGTP core is treated as existing protocol work. This repository explores a
> companion security profile for binding AGTP identity, policy, and task
> material to an accepted aTLS session.

## README Draft

```md
# AGTP aTLS Profile

This repository explores an aTLS-backed security profile for AGTP.

The goal is to make AGTP deployments easier to review for relay resistance,
diversion resistance, same-machine wrong-agent confusion, replay resistance,
and binding-parameter confusion.

This repository does not define the AGTP core protocol. It is intended as a
companion profile, implementation-feedback workspace, and test-vector set for
existing AGTP work.

## Focus

- aTLS session binding for AGTP profile data
- Manager-signed identity grants
- session binding statements tied to the accepted aTLS session
- local expected-value checks for deployment, agent, task, and capability
- negative test vectors for relay, diversion, wrong-agent, replay, downgrade,
  stale evidence, and binding-parameter confusion

## Non-Goals

- redefining AGTP core messages
- replacing AGTP transport choices
- replacing Cocos
- defining a complete OAuth or OIDC profile
- inventing new cryptography

## Relationship to Cocos

The Cocos aTLS work is used as implementation experience. The profile extracts
the security lessons around aTLS binding, identity grants, replay checks, and
fail-closed local policy validation.

## Relationship to AGTP

AGTP core is treated as existing draft work. This profile describes additional
security checks and test vectors that can be proposed as implementation
guidance or draft feedback.
```
