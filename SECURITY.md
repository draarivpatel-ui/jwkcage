# Security policy

## Reporting a vulnerability

Report vulnerabilities through GitHub Security Advisories on the repository page. Do not open a public issue for an unpatched vulnerability.

Include the affected version, a minimal input that demonstrates the problem, the expected behavior, and the actual behavior. Inputs that expose private key material in output, bypass the algorithm confusion defenses, or smuggle duplicate JSON keys past the parser are treated as high priority.

## Scope

`jwkcage` is a defensive boundary library. Its security guarantees cover its own parsing, auditing, and selection logic. It does not perform signature verification, certificate validation, or network access; those remain the responsibility of the integrating application and its cryptographic primitives.

## Hardening commitments

- No runtime or development dependencies.
- Byte, depth, member-count, key-count, and findings budgets on all input paths.
- No network access under any API.
- Audit outputs never echo private key material.
- Findings are capped and truncation is explicit.
