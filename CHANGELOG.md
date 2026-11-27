# Changelog

## 1.0.0

Initial release.

- Strict RFC 7517 and RFC 7518 JWK structural parsing for RSA, EC, OKP, and oct keys.
- Public JWKS auditing with duplicate kid collision detection, key material deduplication, and private parameter leak defense.
- JWS and JWE header auditing with algorithm confusion defense, alg none blocking, inline key injection defense, SSRF perimeter analysis for jku and x5u, and kid injection detection.
- Fail-closed verification key selection with mandatory explicit algorithm allowlists.
- RFC 7638 canonical thumbprints via node:crypto.
- CLI with parse, audit-jwk, audit-jwks, audit-header, thumbprint, strip, and select commands.
- Dual ESM and CommonJS builds with TypeScript declarations.
