# Manager Runtime Notes

The Manager runtime is inherited implementation code. It is not the core
Direct-Agent verifier API for this repository.

Product-facing verifier work should start from:

- `pkg/clients`
- `pkg/atls`
- `pkg/atls/identitypolicy`
- `README.md`
- `PUBLICATION_TODO.md`

The Manager package remains useful for runtime experiments around VM launch,
attestation policy, and local service wiring. Do not use this package as a
source of normative profile behavior.

## Configuration

Current product-facing environment names:

| Variable | Purpose | Default |
| --- | --- | --- |
| `MANAGER_LOG_LEVEL` | Manager log level | `info` |
| `ASB_JAEGER_URL` | OTLP/Jaeger endpoint URL | `http://localhost:4318` |
| `ASB_JAEGER_TRACE_RATIO` | Trace sampling ratio | `1.0` |
| `MANAGER_INSTANCE_ID` | Stable instance identifier | generated when empty |
| `MANAGER_ATTESTATION_POLICY_BINARY_PATH` | Attestation policy helper path | `../../build` |
| `MANAGER_PCR_VALUES` | Expected PCR values | empty |
| `MANAGER_EOS_VERSION` | Expected runtime image version | empty |
| `MANAGER_MAX_VMS` | Maximum managed VM count | `10` |
| `MANAGER_CORIM_SIGNING_KEY` | CoRIM signing key path | empty |

Plaintext listeners are guarded in the runtime server wrapper. Non-loopback
plaintext binds should fail closed unless TLS or aTLS is configured.
