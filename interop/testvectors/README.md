# Hardware-Aware TLS Identity-Binding Test Vectors

These vectors exercise the security profile described in
`docs/hwtls-binding-profile.md` and
`docs/agtp-security-profile-mapping.md`.

They are intentionally protocol-profile vectors, not AGTP core protocol
vectors. AGTP is one reference target for these vectors. They describe what a
verifier should accept or reject after the lower TLS 1.3 session and
post-handshake hardware-attestation gate have produced accepted binding facts.

## Vector Shape

Each vector contains:

- `id`: stable vector id;
- `class`: failure class or positive class;
- `expected_result`: `accept` or `reject`;
- `atls`: accepted lower-layer session facts; the field name is retained for
  compatibility with existing helpers;
- `grant`: Manager-signed Identity Grant payload shape;
- `session_binding`: Session Binding Statement payload shape;
- `local_policy`: verifier-side expected values;
- `replay_cache`: prior replay-cache state;
- `expected_error`: expected failure class when rejected.

The JSON files do not include real signatures yet. The `signature_valid` fields
model the result of signature verification so that the profile logic can be
reviewed before a concrete encoding is fixed.

`diversion-policy-examples.jsonl` contains static diversion-policy examples.
Those examples are policy-level vectors for `pkg/agtp/diversionpolicy`, not
AGTP core protocol vectors.

## Failure Classes

| Class | Expected behavior |
| --- | --- |
| `baseline` | accept when all profile checks match |
| `relay` | reject when session binding does not match the accepted TLS session |
| `diversion` | reject when grant identity differs from local expected deployment policy |
| `wrong-agent` | reject when grant agent differs from local expected agent policy |
| `replay` | reject reused binding or grant identifiers |
| `binding-parameter-confusion` | reject peer-controlled or unsupported binding parameters |
| `downgrade` | reject missing required profile material |
| `stale-evidence` | reject expired grants or binding statements |
| `measurement-mismatch` | reject when appraised platform evidence differs from local policy |
| `policy-denied` | reject locally denied capabilities or scopes |

## Static Diversion Policy Examples

The diversion-policy examples cover:

- allowed client-visible diversion with required client notice;
- hidden diversion rejected without an explicit hidden rule;
- wrong diverted tenant or deployment rejected as a policy miss;
- denied diversion rejected while preserving audit fields.

## Review Rule

The verifier must compare observed values against local expected values. It must
not turn peer-provided values into policy.

Semantic references such as `intent_ref`, `capability_ref`, and `ontology_id`
represent normalized profile identifiers. Test vectors should treat them as
exact values after client-side or local-policy alias resolution. A vector must
not rely on fuzzy matching, prompt similarity, or peer-selected aliases to reach
`accept`.
