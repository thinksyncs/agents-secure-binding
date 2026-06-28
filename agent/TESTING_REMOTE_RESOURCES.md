# Remote Resource Testing Notes

This inherited runtime guide has been intentionally reduced for this repository.
Remote resource execution is outside the Direct-Agent verifier core and should
not be treated as product-level profile evidence.

Before reintroducing remote resource workflows, add a product-specific test
plan that covers:

- TLS or aTLS transport configuration;
- verifier-local expected policy for the requested resource;
- digest verification for downloaded artifacts;
- fail-closed behavior for missing, malformed, or mismatched policy;
- explicit handling of development-only insecure flags.

Do not document `--tls-verify=false`, insecure image policy, or unauthenticated
remote fetch flows as accepted product behavior.
