# jwkcage

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/jwkcage/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/jwkcage)

`jwkcage` is a zero-dependency JWK, JWKS, and JWT header security firewall for Node.js. It implements strict RFC 7517 and RFC 7518 structural validation, RFC 7638 canonical thumbprints, and a fail-closed verification key selector for services that consume JSON Web Keys before any signature or encryption operation is trusted.

The library performs no network access. It audits, it does not fetch.

## Security properties

- Strict structural parsing for RSA, EC, OKP, and oct keys: required members, base64url encoding, minimal-length integer encoding, curve coordinate sizes, `use` and `key_ops` consistency, and byte, depth, member-count, and key-count budgets.
- A strict JSON parser that rejects duplicate object keys at any depth before key material reaches your verifier. Duplicate `alg` or `kid` keys are a classic parser-differential attack surface.
- Prototype pollution defense: `__proto__`, `constructor`, and `prototype` keys are rejected in JSON text and in live objects, and inputs with nonstandard prototypes are refused.
- Algorithm confusion defense: `HS256`/`HS384`/`HS512` against RSA, EC, or OKP keys is detected in key audits, header audits, and key selection. HMAC verification requires explicit `allowSymmetric: true`.
- `alg: "none"` in every capitalization is forbidden in headers, keys, and algorithm allowlists.
- RSA strength policy: modulus below 2048 bits and public exponents below 65537 are critical findings.
- Curve policy: only `P-256`, `P-384`, `P-521`, `Ed25519`, and `Ed448` are allowed by default; the allowlist is caller-configurable.
- Private key leakage defense: `d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, and `oth` in a public JWKS are critical findings, and symmetric `oct` keys can never be published.
- SSRF perimeter analysis for `jku` and `x5u`: HTTPS required, userinfo rejected, loopback, RFC 1918, CGNAT, link-local, cloud metadata, multicast, reserved, documentation, IPv6 ULA, IPv4-mapped and transition-tunnel addresses, integer, octal, hex, and shorthand IPv4 obfuscation, and internal hostnames are all blocked offline.
- Inline key injection defense: `jwk` and `x5c` in JWT headers are critical findings because trusting attacker-supplied key material enables self-signed token acceptance.
- `kid` injection defense: path traversal, SQL injection patterns, CRLF and NUL bytes, shell and template metacharacters, bidirectional overrides, and length abuse.
- Duplicate `kid` collision detection and duplicate key-material detection across a keyset.
- Fail-closed key selection: explicit algorithm allowlists are mandatory, ambiguous selection is an error, unsafe keysets are refused, and private material never survives selection.
- RFC 7638 canonical thumbprints through `node:crypto`, verified against the RFC reference vector.

## Install

```sh
npm install jwkcage
```

Node.js 18 or newer is required. The package has no runtime dependencies. It ships native ESM, generated CommonJS, TypeScript declarations, and a CLI.

## Quick start

```js
import { auditJwks, auditJwtHeader, selectVerificationKey } from 'jwkcage';

const jwksReport = auditJwks(untrustedJwks);
if (!jwksReport.safe) {
  for (const finding of jwksReport.findings) {
    console.error(finding.severity, finding.code, finding.field, finding.message);
  }
  throw new Error('untrusted keyset refused');
}

const headerReport = auditJwtHeader(decodedHeader, {
  algorithms: ['RS256', 'PS256'],
  expectedKty: 'RSA'
});
if (!headerReport.safe) {
  throw new Error('hostile header refused');
}

const key = selectVerificationKey(trustedJwks, decodedHeader, {
  algorithms: ['RS256', 'PS256']
});
// key contains no private material; hand it to your verification primitive.
```

CommonJS is supported too:

```js
const { auditJwks, selectVerificationKey } = require('jwkcage');
```

## API

### `parseJwk(input, options?)`

Strictly parses one JWK from a plain object or JSON string. Throws a typed `JwkCageError` on any structural violation. Returns a deep-frozen key. Use this when you need validity guarantees before cryptographic use.

### `auditJwk(input, options?)`

Audits one JWK without throwing on hostile input. Returns a frozen report with `safe`, `findings`, `counts`, and `truncated`. A report is unsafe when any critical or high finding exists. Options: `allowedCurves`, `bounds`, `context`.

### `auditJwks(input, options?)`

Audits a public keyset: per-key weaknesses propagate into the set report, duplicate kids are critical, leaked private parameters are critical, and symmetric keys are forbidden by default. Options: `requireKid`, `allowedCurves`, `allowSymmetricKeys`, `bounds`.

### `auditJwtHeader(input, options?)`

Audits a decoded JWS or JWE header: algorithm presence and recognition, allowlist enforcement, `expectedKty` confusion defense, inline `jwk` and `x5c` injection, `jku` and `x5u` SSRF analysis, `kid` injection patterns, `crit` extension strictness, and JWE `enc`, `zip`, `epk`, `p2c`, `p2s`, `iv`, and `tag` hygiene. Options: `algorithms`, `expectedKty`, `requireKid`, `kind` (`'jws'`, `'jwe'`, or `'any'`), `bounds`.

### `selectVerificationKey(jwks, header, options)`

Fail-closed selection of the unique key that can verify a header:

- `options.algorithms` is required and must be explicit. `none` can never be allowlisted.
- The keyset must pass `auditJwks` first; hostile keysets are never searched.
- Inline `jwk` or `x5c` in the header aborts selection.
- The key must match the algorithm family and curve, `use` and `key_ops` signing constraints, the `kid` when present, and the key's own pinned `alg` when present.
- Zero matches or multiple matches are both hard errors.
- The returned asymmetric key has private material stripped. HMAC keys are returned intact but only with `allowSymmetric: true`.

### `stripPrivateMaterial(input)`

Returns a deep-frozen copy of a JWK with `d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, and `oth` removed.

### `computeJwkThumbprint(input, hashAlgorithm?)`

RFC 7638 canonical thumbprint using `sha256` (default), `sha384`, or `sha512`. Only the required canonical members participate, so `kid`, `use`, and extension members never change the digest.

## CLI

```sh
jwkcage parse <jwk-json>
jwkcage audit-jwk <jwk-json> [--json]
jwkcage audit-jwks <jwks-json> [--json]
jwkcage audit-header <header-json> [--json]
jwkcage thumbprint <jwk-json> [sha256|sha384|sha512]
jwkcage strip <jwk-json>
jwkcage select <jwks-json> <header-json> --alg RS256[,PS256] [--allow-symmetric]
```

Pass `-` instead of a JSON argument to read from standard input. Exit codes: `0` success or safe, `1` unsafe or invalid input, `2` usage error.

## Threat model

In scope: parser differentials, algorithm confusion, weak keys, key leakage, hostile key identifiers, key selection ambiguity, SSRF through key discovery URLs, inline key injection, prototype pollution, and resource exhaustion through oversized input.

Out of scope: signature verification itself, certificate chain validation, network fetching of `jku` or `x5u` targets, and JWT claims validation. `jwkcage` decides whether key material is safe to use; your cryptographic library performs the primitive.

## Error handling

`parseJwk`, `selectVerificationKey`, `stripPrivateMaterial`, and `computeJwkThumbprint` throw typed `JwkCageError` instances with stable `code` strings. Audit functions return reports instead of throwing on hostile input, so attacker-controlled data can never crash the audit path. Programmer errors such as unknown options still throw, because silently ignoring a misspelled security option would be a vulnerability.

## License

MIT
