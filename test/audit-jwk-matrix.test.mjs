import assert from 'node:assert/strict';
import { test } from 'node:test';
import { auditJwk } from '../src/index.mjs';
import {
  cloneKey,
  EC_PUBLIC,
  ED_PUBLIC,
  expectNoFinding,
  expectSafe,
  expectUnsafe,
  matrix,
  OCT_KEY,
  RSA_PRIVATE,
  RSA_PUBLIC,
  symmetricKey
} from './helpers.mjs';

const safeCases = [
  { name: 'rsa 2048 public', input: RSA_PUBLIC },
  { name: 'ec p256 public', input: EC_PUBLIC },
  { name: 'ed25519 public', input: ED_PUBLIC },
  { name: 'rsa json string', input: JSON.stringify(RSA_PUBLIC) },
  { name: 'rsa no alg', input: { kty: 'RSA', n: RSA_PUBLIC.n, e: RSA_PUBLIC.e } },
  { name: 'rsa no kid', input: { kty: 'RSA', n: RSA_PUBLIC.n, e: RSA_PUBLIC.e, alg: 'RS256' } },
  { name: 'rsa ps alg', input: { ...cloneKey(RSA_PUBLIC), alg: 'PS256' } },
  { name: 'rsa rs384', input: { ...cloneKey(RSA_PUBLIC), alg: 'RS384' } },
  { name: 'rsa rs512', input: { ...cloneKey(RSA_PUBLIC), alg: 'RS512' } },
  { name: 'rsa ps384', input: { ...cloneKey(RSA_PUBLIC), alg: 'PS384' } },
  { name: 'rsa ps512', input: { ...cloneKey(RSA_PUBLIC), alg: 'PS512' } },
  { name: 'rsa oaep enc', input: { ...cloneKey(RSA_PUBLIC), alg: 'RSA-OAEP', use: 'enc', key_ops: ['wrapKey'] } },
  { name: 'rsa oaep-256', input: { ...cloneKey(RSA_PUBLIC), alg: 'RSA-OAEP-256', use: 'enc' } },
  { name: 'ec es256', input: { ...cloneKey(EC_PUBLIC), alg: 'ES256' } },
  { name: 'ecdh-es enc', input: { ...cloneKey(EC_PUBLIC), alg: 'ECDH-ES', use: 'enc', key_ops: ['deriveKey'] } },
  { name: 'okp eddsa', input: ED_PUBLIC },
  { name: 'rsa private held locally', input: RSA_PRIVATE, skipPrivateCheck: true },
  { name: 'kid with simple charset', input: { ...cloneKey(RSA_PUBLIC), kid: 'key-2024-01' } },
  { name: 'kid with digits', input: { ...cloneKey(RSA_PUBLIC), kid: '123456' } },
  { name: 'x5u public https', input: { ...cloneKey(RSA_PUBLIC), x5u: 'https://certs.example.com/ca.pem' } },
  { name: 'x5c valid chain', input: { ...cloneKey(RSA_PUBLIC), x5c: ['MIIB', 'MIIB'] } }
];

matrix('auditJwk safe baseline', safeCases, ({ input, skipPrivateCheck }) => {
  const report = auditJwk(input);
  if (skipPrivateCheck === true) {
    expectNoFinding(report, 'RSA_MODULUS_TOO_SMALL');
    expectNoFinding(report, 'ALG_KTY_MISMATCH');
  } else {
    expectSafe(report);
  }
});

function rsaWithModulusBits(bits) {
  const byteLength = Math.ceil(bits / 8);
  const topBits = bits - (byteLength - 1) * 8;
  const bytes = Buffer.alloc(byteLength);
  bytes[0] = 1 << (topBits - 1);
  bytes[byteLength - 1] |= 1;
  return { kty: 'RSA', n: bytes.toString('base64url'), e: 'AQAB' };
}

const weakRsaCases = [];
for (const bits of [512, 1024, 2040, 2047]) {
  weakRsaCases.push({ name: 'rsa ' + bits + ' bit modulus', input: rsaWithModulusBits(bits), code: 'RSA_MODULUS_TOO_SMALL' });
}
for (const [exponentBytes, label] of [
  ['Aw', 'exponent 3'],
  ['AQ', 'exponent 1'],
  ['EQ', 'exponent 17'],
  ['ESE', 'exponent 4370']
]) {
  weakRsaCases.push({
    name: 'rsa ' + label,
    input: { ...cloneKey(RSA_PUBLIC), e: exponentBytes },
    code: 'RSA_EXPONENT_TOO_SMALL'
  });
}
weakRsaCases.push({
  name: 'rsa even large exponent',
  input: { ...cloneKey(RSA_PUBLIC), e: 'AQAAAA' },
  code: 'RSA_EXPONENT_EVEN'
});

matrix('auditJwk weak RSA detection', weakRsaCases, ({ input, code }) => {
  expectUnsafe(auditJwk(input), code);
});

test('auditJwk rsa 2048 exactly at floor is acceptable', () => {
  const report = auditJwk(rsaWithModulusBits(2048));
  expectNoFinding(report, 'RSA_MODULUS_TOO_SMALL');
});

test('auditJwk rsa 4096 acceptable', () => {
  const report = auditJwk(rsaWithModulusBits(4096));
  expectNoFinding(report, 'RSA_MODULUS_TOO_SMALL');
});

const curveCases = [];
for (const crv of ['P-256', 'P-384', 'P-521']) {
  curveCases.push({
    name: 'ec curve allowed ' + crv,
    input: { kty: 'EC', crv, x: 'B' + 'A'.repeat(crv === 'P-256' ? 42 : crv === 'P-384' ? 63 : 87), y: 'B' + 'A'.repeat(crv === 'P-256' ? 42 : crv === 'P-384' ? 63 : 87) },
    expectSafe: true
  });
}
curveCases.push({
  name: 'ed448 allowed',
  input: { kty: 'OKP', crv: 'Ed448', x: 'B' + 'A'.repeat(75) },
  expectSafe: true
});
curveCases.push({
  name: 'x25519 not in default allowlist',
  input: { kty: 'OKP', crv: 'X25519', x: 'B' + 'A'.repeat(42) },
  code: 'CURVE_NOT_ALLOWED'
});
curveCases.push({
  name: 'custom allowlist permits x25519',
  input: { kty: 'OKP', crv: 'X25519', x: 'B' + 'A'.repeat(42) },
  options: { allowedCurves: ['X25519'] },
  expectSafe: true
});
curveCases.push({
  name: 'custom allowlist forbids p256',
  input: EC_PUBLIC,
  options: { allowedCurves: ['P-384'] },
  code: 'CURVE_NOT_ALLOWED'
});
curveCases.push({
  name: 'empty allowlist forbids everything',
  input: EC_PUBLIC,
  options: { allowedCurves: [] },
  code: 'CURVE_NOT_ALLOWED'
});

matrix('auditJwk curve policy', curveCases, ({ input, options, code, expectSafe: safe }) => {
  const report = options === undefined ? auditJwk(input) : auditJwk(input, options);
  if (safe === true) expectSafe(report);
  else expectUnsafe(report, code);
});

const algConfusionCases = [];
for (const [alg, family] of [
  ['HS256', 'rsa'], ['HS384', 'rsa'], ['HS512', 'rsa'],
  ['HS256', 'ec'], ['HS256', 'okp'],
  ['RS256', 'oct'], ['RS256', 'ec'], ['ES256', 'rsa'], ['EdDSA', 'rsa'], ['EdDSA', 'ec']
]) {
  const base = family === 'rsa' ? RSA_PUBLIC : family === 'ec' ? EC_PUBLIC : family === 'okp' ? ED_PUBLIC : OCT_KEY;
  algConfusionCases.push({
    name: alg + ' against ' + family + ' key',
    input: { ...cloneKey(base), alg },
    code: 'ALG_KTY_MISMATCH'
  });
}

matrix('auditJwk algorithm-keytype confusion', algConfusionCases, ({ input, code }) => {
  expectUnsafe(auditJwk(input), code);
});

const algCases = [
  { name: 'alg none lowercase', alg: 'none' },
  { name: 'alg none capitalized', alg: 'None' },
  { name: 'alg none uppercase', alg: 'NONE' },
  { name: 'alg none mixed', alg: 'nOnE' }
];
matrix('auditJwk alg none variants', algCases, ({ alg }) => {
  expectUnsafe(auditJwk({ ...cloneKey(RSA_PUBLIC), alg }), 'ALG_NONE');
});

const deprecatedCases = [
  { name: 'RSA1_5', alg: 'RSA1_5', expectCodes: ['ALG_DEPRECATED'] },
  { name: 'RS1', alg: 'RS1', expectCodes: ['ALG_DEPRECATED'] },
  { name: 'HS1', alg: 'HS1', expectCodes: ['ALG_DEPRECATED'] }
];
matrix('auditJwk deprecated algorithms', deprecatedCases, ({ alg }) => {
  expectUnsafe(auditJwk({ ...cloneKey(RSA_PUBLIC), alg }), 'ALG_DEPRECATED');
});

const privateLeakCases = [];
for (const param of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
  privateLeakCases.push({
    name: 'rsa private param ' + param,
    input: { ...cloneKey(RSA_PUBLIC), [param]: RSA_PRIVATE[param] === undefined ? 'AQAB' : RSA_PRIVATE[param], ...(param !== 'd' ? { d: RSA_PRIVATE.d, p: RSA_PRIVATE.p, q: RSA_PRIVATE.q, dp: RSA_PRIVATE.dp, dq: RSA_PRIVATE.dq, qi: RSA_PRIVATE.qi } : {}) },
    code: 'PRIVATE_MATERIAL_PRESENT'
  });
}
privateLeakCases.push({
  name: 'rsa oth multi prime leak',
  input: { ...cloneKey(RSA_PRIVATE), oth: [{ r: 'AQ', d: 'AQ', t: 'AQ' }] },
  code: 'PRIVATE_MATERIAL_PRESENT'
});

matrix('auditJwk private material detection', privateLeakCases, ({ input, code }) => {
  expectUnsafe(auditJwk(input), code);
});

test('auditJwk oct key flags symmetric material warning', () => {
  const report = auditJwk(OCT_KEY);
  assert.ok(report.findings.some((hit) => hit.code === 'SYMMETRIC_KEY_MATERIAL'));
});

test('auditJwk oct short key for HS256 is critical', () => {
  const key = { kty: 'oct', k: symmetricKey(16), alg: 'HS256' };
  expectUnsafe(auditJwk(key), 'OCT_KEY_TOO_SHORT');
});

test('auditJwk oct 32 byte key for HS256 passes strength', () => {
  const key = { kty: 'oct', k: symmetricKey(32), alg: 'HS256' };
  const report = auditJwk(key);
  expectNoFinding(report, 'OCT_KEY_TOO_SHORT');
});

test('auditJwk oct 48 byte key satisfies HS384', () => {
  const key = { kty: 'oct', k: symmetricKey(48), alg: 'HS384' };
  const report = auditJwk(key);
  expectNoFinding(report, 'OCT_KEY_TOO_SHORT');
});

test('auditJwk oct 32 byte key fails HS384 floor', () => {
  const key = { kty: 'oct', k: symmetricKey(32), alg: 'HS384' };
  expectUnsafe(auditJwk(key), 'OCT_KEY_TOO_SHORT');
});

test('auditJwk oct 64 byte key satisfies HS512', () => {
  const key = { kty: 'oct', k: symmetricKey(64), alg: 'HS512' };
  const report = auditJwk(key);
  expectNoFinding(report, 'OCT_KEY_TOO_SHORT');
});

const useOpsCases = [
  { name: 'use sig with encrypt op', use: 'sig', ops: ['verify', 'encrypt'], expect: 'USE_KEY_OPS_MISMATCH' },
  { name: 'use sig with wrapKey op', use: 'sig', ops: ['verify', 'wrapKey'], expect: 'USE_KEY_OPS_MISMATCH' },
  { name: 'use enc with sign op', use: 'enc', ops: ['decrypt', 'sign'], expect: 'USE_KEY_OPS_MISMATCH' },
  { name: 'use enc with verify op', use: 'enc', ops: ['encrypt', 'verify'], expect: 'USE_KEY_OPS_MISMATCH' }
];
matrix('auditJwk use key_ops mismatch', useOpsCases, ({ use, ops, expect: code }) => {
  expectUnsafe(auditJwk({ ...cloneKey(RSA_PUBLIC), use, key_ops: ops }), code);
});

const consistentOps = [
  { name: 'sig with verify', use: 'sig', ops: ['verify'] },
  { name: 'sig with sign verify', use: 'sig', ops: ['sign', 'verify'] },
  { name: 'enc with encrypt decrypt', use: 'enc', ops: ['encrypt', 'decrypt'] },
  { name: 'enc with wrap unwrap', use: 'enc', ops: ['wrapKey', 'unwrapKey'] },
  { name: 'no use with mixed ops', use: undefined, ops: ['verify', 'encrypt'] },
  { name: 'derive ops no use', use: undefined, ops: ['deriveKey', 'deriveBits'] }
];
matrix('auditJwk consistent use key_ops', consistentOps, ({ use, ops }) => {
  const key = cloneKey(RSA_PUBLIC);
  if (use === undefined) delete key.use;
  else key.use = use;
  key.key_ops = ops;
  expectNoFinding(auditJwk(key), 'USE_KEY_OPS_MISMATCH');
});

const kidAttackCases = [
  { name: 'path traversal dotdot slash', kid: '../../etc/passwd', code: 'KID_PATH_TRAVERSAL' },
  { name: 'path traversal dotdot backslash', kid: '..\\..\\windows\\system32', code: 'KID_PATH_TRAVERSAL' },
  { name: 'bare dotdot', kid: '..', code: 'KID_PATH_TRAVERSAL' },
  { name: 'forward slash', kid: 'keys/rsa-1', code: 'KID_PATH_SEPARATOR' },
  { name: 'backslash', kid: 'keys\\rsa-1', code: 'KID_PATH_SEPARATOR' },
  { name: 'sqli union select', kid: "1' UNION SELECT password--", code: 'KID_SQLI_PATTERN' },
  { name: 'sqli or trivially true', kid: "' OR '1'='1", code: 'KID_SQLI_PATTERN' },
  { name: 'sqli drop table', kid: "x'; DROP TABLE keys;--", code: 'KID_SQLI_PATTERN' },
  { name: 'nul byte', kid: 'key\0', code: 'KID_CONTROL_INJECTION' },
  { name: 'crlf injection', kid: 'key\r\nInjected: yes', code: 'KID_CONTROL_INJECTION' },
  { name: 'newline only', kid: 'key\nnext', code: 'KID_CONTROL_INJECTION' },
  { name: 'carriage return only', kid: 'key\rnext', code: 'KID_CONTROL_INJECTION' },
  { name: 'tab control', kid: 'key\tx', code: 'KID_CONTROL_INJECTION' },
  { name: 'bell control', kid: 'key\x07x', code: 'KID_CONTROL_INJECTION' },
  { name: 'command substitution backtick', kid: 'key`id`', code: 'KID_METACHARACTERS' },
  { name: 'shell dollar subst', kid: 'key$(id)', code: 'KID_METACHARACTERS' },
  { name: 'shell pipe', kid: 'key|id', code: 'KID_METACHARACTERS' },
  { name: 'shell semicolon', kid: 'key;id', code: 'KID_METACHARACTERS' },
  { name: 'shell ampersand', kid: 'key&id', code: 'KID_METACHARACTERS' },
  { name: 'template angle', kid: 'key<script>', code: 'KID_METACHARACTERS' },
  { name: 'query string', kid: 'key?x=1', code: 'KID_METACHARACTERS' },
  { name: 'fragment', kid: 'key#frag', code: 'KID_METACHARACTERS' },
  { name: 'percent encoding', kid: 'key%2e%2e', code: 'KID_METACHARACTERS' },
  { name: 'sql equals', kid: "key'='", code: 'KID_METACHARACTERS' },
  { name: 'overlong kid', kid: 'k'.repeat(200), code: 'KID_TOO_LONG' },
  { name: 'empty kid', kid: '', code: 'KID_EMPTY' },
  { name: 'bidi override', kid: 'key\u202edliats', code: 'KID_BIDI_INJECTION' }
];

matrix('auditJwk kid injection detection', kidAttackCases, ({ kid, code }) => {
  expectUnsafe(auditJwk({ ...cloneKey(RSA_PUBLIC), kid }), code);
});

const kidSafeCases = [
  { name: 'uuid', kid: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' },
  { name: 'thumbprint style', kid: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs' },
  { name: 'simple numeric', kid: '42' },
  { name: 'simple alpha', kid: 'signing-key-one' },
  { name: 'underscores dots', kid: 'key_2024.01' },
  { name: 'max length exactly', kid: 'k'.repeat(128) }
];
matrix('auditJwk safe kids', kidSafeCases, ({ kid }) => {
  const report = auditJwk({ ...cloneKey(RSA_PUBLIC), kid });
  assert.ok(!report.findings.some((hit) => hit.field === 'kid' && (hit.severity === 'critical' || hit.severity === 'high')), 'safe kid flagged: ' + JSON.stringify(report.findings.filter((f) => f.field === 'kid')));
});

test('auditJwk malformed input returns critical report instead of throwing', () => {
  const report = auditJwk('not json at all');
  assert.equal(report.safe, false);
  assert.ok(report.counts.critical > 0);
});

test('auditJwk structurally invalid key returns critical report', () => {
  const report = auditJwk({ kty: 'RSA' });
  assert.equal(report.safe, false);
  assert.ok(report.counts.critical > 0);
});

test('auditJwk report shape is frozen', () => {
  const report = auditJwk(RSA_PUBLIC);
  assert.ok(Object.isFrozen(report));
  assert.ok(Object.isFrozen(report.findings));
  assert.ok(Object.isFrozen(report.counts));
});

test('auditJwk counts sum correctly', () => {
  const report = auditJwk({ ...cloneKey(RSA_PUBLIC), alg: 'none', kid: '../x' });
  const total = report.counts.critical + report.counts.high + report.counts.medium + report.counts.low + report.counts.info;
  assert.equal(total, report.findings.length);
});

test('auditJwk rejects unknown options', () => {
  assert.throws(() => auditJwk(RSA_PUBLIC, { wat: 1 }), /JWKCAGE_INVALID_OPTIONS/u);
});

test('auditJwk safe false requires critical or high only', () => {
  const report = auditJwk(RSA_PUBLIC);
  assert.equal(report.safe, true);
  assert.equal(report.counts.critical, 0);
  assert.equal(report.counts.high, 0);
});

const x5uAttackCases = [
  { name: 'http cleartext', x5u: 'http://certs.example.com/ca.pem', code: 'ENDPOINT_URL_NOT_HTTPS' },
  { name: 'loopback ip', x5u: 'https://127.0.0.1/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'rfc1918 class a', x5u: 'https://10.0.0.5/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'rfc1918 class b', x5u: 'https://172.16.0.1/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'rfc1918 class c', x5u: 'https://192.168.1.1/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'link local metadata', x5u: 'https://169.254.169.254/latest/meta-data', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'cgnat range', x5u: 'https://100.64.0.1/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'integer ip obfuscation', x5u: 'https://2130706433/ca.pem', code: 'ENDPOINT_URL_IPV4_OBFUSCATED' },
  { name: 'hex ip obfuscation', x5u: 'https://0x7f000001/ca.pem', code: 'ENDPOINT_URL_IPV4_OBFUSCATED' },
  { name: 'octal ip obfuscation', x5u: 'https://0177.0.0.1/ca.pem', code: 'ENDPOINT_URL_IPV4_OBFUSCATED' },
  { name: 'shorthand ip', x5u: 'https://127.1/ca.pem', code: 'ENDPOINT_URL_IPV4_OBFUSCATED' },
  { name: 'localhost name', x5u: 'https://localhost/ca.pem', code: 'ENDPOINT_URL_INTERNAL_HOST' },
  { name: 'localhost subdomain', x5u: 'https://x.localhost/ca.pem', code: 'ENDPOINT_URL_INTERNAL_HOST' },
  { name: 'internal tld', x5u: 'https://vault.internal/ca.pem', code: 'ENDPOINT_URL_INTERNAL_HOST' },
  { name: 'local tld', x5u: 'https://printer.local/ca.pem', code: 'ENDPOINT_URL_INTERNAL_HOST' },
  { name: 'single label', x5u: 'https://intranet/ca.pem', code: 'ENDPOINT_URL_INTERNAL_HOST' },
  { name: 'ipv6 loopback', x5u: 'https://[::1]/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'ipv6 unique local', x5u: 'https://[fd00::1]/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'ipv6 link local', x5u: 'https://[fe80::1]/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'ipv4 mapped ipv6', x5u: 'https://[::ffff:127.0.0.1]/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'userinfo credential', x5u: 'https://user:pass@certs.example.com/ca.pem', code: 'ENDPOINT_URL_CREDENTIALS' },
  { name: 'multicast ip', x5u: 'https://224.0.0.1/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' },
  { name: 'zero ip', x5u: 'https://0.0.0.0/ca.pem', code: 'ENDPOINT_URL_IP_NOT_PUBLIC' }
];
matrix('auditJwk x5u SSRF perimeter', x5uAttackCases, ({ x5u, code }) => {
  expectUnsafe(auditJwk({ ...cloneKey(RSA_PUBLIC), x5u }), code);
});

test('auditJwk documentation ip blocked', () => {
  expectUnsafe(auditJwk({ ...cloneKey(RSA_PUBLIC), x5u: 'https://192.0.2.1/ca.pem' }), 'ENDPOINT_URL_IP_NOT_PUBLIC');
});
