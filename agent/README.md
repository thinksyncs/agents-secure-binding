# Agent Runtime Notes

The Agent runtime is inherited implementation code. It is not the core
Direct-Agent verifier API for this repository.

Use it only as an experimental runtime harness around the profile helpers in:

- `pkg/clients`
- `pkg/atls`
- `pkg/atls/identitypolicy`

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `AGENT_LOG_LEVEL` | Agent log level | `debug` |
| `AGENT_VMPL` | VM privilege level for attestation requests | `2` |
| `AGENT_GRPC_HOST` | Agent gRPC bind host | `0.0.0.0` |
| `AGENT_CVM_CA_URL` | Optional CA service URL | empty |
| `AGENT_CVM_ID` | Runtime CVM identifier | empty |
| `AGENT_CERTS_TOKEN` | Certificate request token | empty |
| `AGENT_MAA_URL` | Azure MAA URL | `https://sharedeus2.eus2.attest.azure.net` |
| `ATTESTATION_SERVICE_SOCKET` | Attestation service Unix socket | `/run/agents-secure-binding/attestation.sock` |

Runtime plaintext paths are expected to stay on Unix sockets or loopback unless
TLS or aTLS is explicitly configured.
