# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Use the private GitHub Security Advisories form: [Report a vulnerability](https://github.com/draarivpatel-ui/jwkcage/security/advisories/new). Do not open a public issue, pull request, or discussion with exploit details, secrets, private endpoints, or personal data.

Include the affected version, a minimal JWK, JWKS, or JWT header fixture with private key material redacted, the API used, the expected security behavior, and the actual behavior or finding code.

## Disclosure timeline

We acknowledge reports within 48 hours. We aim to confirm or reject the report within 7 days, prepare a fix as soon as practical, and coordinate public disclosure with the reporter. Unless a shorter deadline is required by an actively exploited issue, please allow up to 90 days for a coordinated fix and disclosure.

## Scope

In scope:

- Duplicate-key parser differentials in JWK, JWKS, or JWT header JSON
- Algorithm confusion, `alg: "none"` acceptance, or symmetric and asymmetric key confusion
- Private or symmetric key material exposed through a public JWKS path
- SSRF perimeter bypasses in `jku` or `x5u` validation
- RFC 7517, RFC 7518, or RFC 7638 structural validation bypasses with security impact
- Key selection behavior that chooses a key outside the caller's algorithm, use, or key-operation policy

## Out of scope

Signature verification, certificate validation, network access, and vulnerabilities in cryptographic primitives are outside the library boundary and remain the responsibility of the integrating application. Inputs already trusted by the caller are also out of scope.

## Hardening notes

The package has zero runtime dependencies. Input budgets, fail-closed validation, deterministic tests, and property-based fuzz tests are part of the maintenance bar. A report that the library marks unsafe must block the operation in the caller; audit output is a boundary signal, not proof that a downstream system is safe.

## Disclosure history

No published advisories yet. Fixed versions will be listed here with their advisory links.
