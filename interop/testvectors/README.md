# AGTP aTLS Security-Profile Test Vectors

These vectors exercise the security profile described in
`docs/agtp-atls-binding-profile.md` and
`docs/agtp-security-profile-mapping.md`.

They are intentionally protocol-profile vectors, not AGTP core protocol
vectors. They describe what a verifier should accept or reject after the lower
aTLS session has already produced accepted binding facts.

## Vector Shape

Each vector contains:

- `id`: stable vector id;
- `class`: failure class or positive class;
- `expected_result`: `accept` or `reject`;
- `atls`: accepted lower-layer session facts;
- `grant`: Manager-signed Identity Grant payload shape;
- `session_binding`: Session Binding Statement payload shape;
- `local_policy`: verifier-side expected values;
- `replay_cache`: prior replay-cache state;
- `expected_error`: expected failure class when rejected.

The JSON files do not include real signatures yet. The `signature_valid` fields
model the result of signature verification so that the profile logic can be
reviewed before a concrete encoding is fixed.

## Failure Classes

| Class | Expected behavior |
| --- | --- |
| `baseline` | accept when all profile checks match |
| `relay` | reject when session binding does not match the accepted aTLS session |
| `diversion` | reject when grant identity differs from local expected deployment policy |
| `wrong-agent` | reject when grant agent differs from local expected agent policy |
| `replay` | reject reused binding or grant identifiers |
| `binding-parameter-confusion` | reject peer-controlled or unsupported binding parameters |
| `downgrade` | reject missing required profile material |
| `stale-evidence` | reject expired grants or binding statements |
| `measurement-mismatch` | reject when appraised platform evidence differs from local policy |
| `policy-denied` | reject locally denied capabilities or scopes |

## Review Rule

The verifier must compare observed values against local expected values. It must
not turn peer-provided values into policy.
