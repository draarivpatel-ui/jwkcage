import assert from 'node:assert/strict';
import { test } from 'node:test';
import { auditJwks } from '../src/index.mjs';
import {
  cloneKey,
  EC_PUBLIC,
  ED_PUBLIC,
  expectSafe,
  expectUnsafe,
  matrix,
  OCT_KEY,
  publicJwks,
  RSA_PRIVATE,
  RSA_PUBLIC
} from './helpers.mjs';

const safeSets = [
  { name: 'single rsa', input: publicJwks([RSA_PUBLIC]) },
  { name: 'rsa plus ec rotation', input: publicJwks([RSA_PUBLIC, EC_PUBLIC]) },
  { name: 'three family rotation', input: publicJwks([RSA_PUBLIC, EC_PUBLIC, ED_PUBLIC]) },
  { name: 'jwks json string', input: JSON.stringify(publicJwks([RSA_PUBLIC])) },
  { name: 'jwks with extension member', input: { ...publicJwks([RSA_PUBLIC]), issuer: 'https://issuer.example.com' } },
  { name: 'keys with distinct kids', input: publicJwks([{ ...cloneKey(RSA_PUBLIC), kid: 'a' }, { ...cloneKey(EC_PUBLIC), kid: 'b' }]) }
];
matrix('auditJwks safe sets', safeSets, ({ input }) => {
  expectSafe(auditJwks(input));
});

const malformedSets = [
  { name: 'null', input: null },
  { name: 'array', input: [] },
  { name: 'string garbage', input: 'nope' },
  { name: 'missing keys member', input: {} },
  { name: 'keys not array', input: { keys: {} } },
  { name: 'keys string', input: { keys: 'x' } },
  { name: 'keys null', input: { keys: null } },
  { name: 'key entry null', input: { keys: [null] } },
  { name: 'key entry string', input: { keys: ['x'] } },
  { name: 'key entry number', input: { keys: [5] } },
  { name: 'key entry array', input: { keys: [[]] } },
  { name: 'key entry invalid kty', input: { keys: [{ kty: 'BAD' }] } },
  { name: 'key entry missing kty', input: { keys: [{ kid: 'a' }] } }
];
matrix('auditJwks malformed sets', malformedSets, ({ input }) => {
  const report = auditJwks(input);
  assert.equal(report.safe, false);
  assert.ok(report.counts.critical > 0, 'expected critical findings');
});

test('auditJwks rejects oversized key count', () => {
  const keys = [];
  for (let index = 0; index < 130; index += 1) keys.push({ ...cloneKey(RSA_PUBLIC), kid: 'k' + index });
  expectUnsafe(auditJwks({ keys }), 'JWKS_TOO_MANY_KEYS');
});

test('auditJwks respects custom maxKeys bound', () => {
  const set = publicJwks([RSA_PUBLIC, EC_PUBLIC]);
  expectUnsafe(auditJwks(set, { bounds: { maxKeys: 1 } }), 'JWKS_TOO_MANY_KEYS');
});

test('auditJwks empty keys array is a medium warning but not unsafe', () => {
  const report = auditJwks({ keys: [] });
  assert.equal(report.safe, true);
  assert.ok(report.findings.some((hit) => hit.code === 'JWKS_EMPTY'));
});

const privateLeakCases = [];
for (const param of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
  privateLeakCases.push({
    name: 'rsa leak param ' + param,
    build() {
      const key = cloneKey(RSA_PRIVATE);
      for (const other of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']) {
        if (other !== param) delete key[other];
      }
      if (['p', 'dp', 'dq', 'qi'].includes(param)) {
        key.p = RSA_PRIVATE.p;
        key.q = RSA_PRIVATE.q;
        key.d = RSA_PRIVATE.d;
      }
      return publicJwks([key]);
    },
    code: 'PUBLIC_JWKS_PRIVATE_LEAK'
  });
}
privateLeakCases.push({
  name: 'rsa oth leak',
  build: () => publicJwks([{ ...cloneKey(RSA_PRIVATE), oth: [{ r: 'AQ', d: 'AQ', t: 'AQ' }] }]),
  code: 'PUBLIC_JWKS_PRIVATE_LEAK'
});
privateLeakCases.push({
  name: 'oct symmetric key published',
  build: () => publicJwks([OCT_KEY]),
  code: 'PUBLIC_JWKS_SYMMETRIC_KEY'
});
privateLeakCases.push({
  name: 'oct key leak k param',
  build: () => publicJwks([OCT_KEY]),
  code: 'PUBLIC_JWKS_PRIVATE_LEAK'
});
privateLeakCases.push({
  name: 'leak in second key of rotation',
  build: () => publicJwks([RSA_PUBLIC, RSA_PRIVATE]),
  code: 'PUBLIC_JWKS_PRIVATE_LEAK'
});

matrix('auditJwks private material exposure', privateLeakCases, ({ build, code }) => {
  expectUnsafe(auditJwks(build()), code);
});

test('auditJwks duplicate exact kid is critical', () => {
  const a = { ...cloneKey(RSA_PUBLIC), kid: 'same' };
  const b = { ...cloneKey(EC_PUBLIC), kid: 'same' };
  expectUnsafe(auditJwks(publicJwks([a, b])), 'KID_DUPLICATE_COLLISION');
});

test('auditJwks duplicate kid across three keys detected', () => {
  const a = { ...cloneKey(RSA_PUBLIC), kid: 'one' };
  const b = { ...cloneKey(EC_PUBLIC), kid: 'two' };
  const c = { ...cloneKey(ED_PUBLIC), kid: 'one' };
  expectUnsafe(auditJwks(publicJwks([a, b, c])), 'KID_DUPLICATE_COLLISION');
});

test('auditJwks same key material under two kids is flagged', () => {
  const a = { ...cloneKey(RSA_PUBLIC), kid: 'first' };
  const b = { ...cloneKey(RSA_PUBLIC), kid: 'second' };
  expectUnsafe(auditJwks(publicJwks([a, b])), 'KEY_MATERIAL_DUPLICATE');
});

test('auditJwks missing kid in multi-key set is unsafe', () => {
  const a = cloneKey(RSA_PUBLIC);
  delete a.kid;
  const b = { ...cloneKey(EC_PUBLIC), kid: 'ec-1' };
  expectUnsafe(auditJwks(publicJwks([a, b])), 'KID_MISSING');
});

test('auditJwks missing kid in single key set is tolerated by default', () => {
  const a = cloneKey(RSA_PUBLIC);
  delete a.kid;
  const report = auditJwks(publicJwks([a]));
  assert.ok(!report.findings.some((hit) => hit.code === 'KID_MISSING'));
});

test('auditJwks requireKid policy enforces single key kid', () => {
  const a = cloneKey(RSA_PUBLIC);
  delete a.kid;
  expectUnsafe(auditJwks(publicJwks([a]), { requireKid: true }), 'KID_REQUIRED');
});

test('auditJwks requireKid passes when kid present', () => {
  expectSafe(auditJwks(publicJwks([RSA_PUBLIC]), { requireKid: true }));
});

test('auditJwks per-key findings carry keyIndex', () => {
  const report = auditJwks(publicJwks([RSA_PUBLIC, { ...cloneKey(EC_PUBLIC), alg: 'HS256' }]));
  const hit = report.findings.find((finding) => finding.code === 'ALG_KTY_MISMATCH');
  assert.ok(hit !== undefined);
  assert.equal(hit.keyIndex, 1);
  assert.ok(hit.field.startsWith('keys[1]'));
});

test('auditJwks report counts are consistent', () => {
  const report = auditJwks(publicJwks([RSA_PRIVATE]));
  const total = report.counts.critical + report.counts.high + report.counts.medium + report.counts.low + report.counts.info;
  assert.equal(total, report.findings.length);
});

test('auditJwks report is frozen', () => {
  const report = auditJwks(publicJwks([RSA_PUBLIC]));
  assert.ok(Object.isFrozen(report));
  assert.ok(Object.isFrozen(report.findings));
});

test('auditJwks duplicate keys in json string input rejected', () => {
  const json = '{"keys":[{"kty":"RSA","kty":"EC"}]}';
  const report = auditJwks(json);
  assert.equal(report.safe, false);
  assert.ok(report.findings.some((hit) => hit.code === 'DUPLICATE_JSON_KEY'));
});

test('auditJwks pollution in json string rejected', () => {
  const json = '{"keys":[],"__proto__":{"x":1}}';
  const report = auditJwks(json);
  assert.equal(report.safe, false);
  assert.ok(report.findings.some((hit) => hit.code === 'PROTOTYPE_POLLUTION'));
});

const weakKeyInSetCases = [
  {
    name: 'weak rsa modulus in set',
    build: () => {
      const bytes = Buffer.alloc(128);
      bytes[0] = 0x80;
      bytes[127] = 1;
      return publicJwks([{ kty: 'RSA', n: bytes.toString('base64url'), e: 'AQAB', kid: 'weak' }]);
    },
    code: 'RSA_MODULUS_TOO_SMALL'
  },
  {
    name: 'tiny exponent in set',
    build: () => publicJwks([{ kty: 'RSA', n: RSA_PUBLIC.n, e: 'Aw', kid: 'weak' }]),
    code: 'RSA_EXPONENT_TOO_SMALL'
  },
  {
    name: 'x5u ssrf in set key',
    build: () => publicJwks([{ ...cloneKey(RSA_PUBLIC), x5u: 'https://169.254.169.254/x' }]),
    code: 'ENDPOINT_URL_IP_NOT_PUBLIC'
  },
  {
    name: 'malicious kid in set',
    build: () => publicJwks([{ ...cloneKey(RSA_PUBLIC), kid: '../evil' }]),
    code: 'KID_PATH_TRAVERSAL'
  },
  {
    name: 'use ops mismatch in set',
    build: () => publicJwks([{ ...cloneKey(RSA_PUBLIC), use: 'sig', key_ops: ['verify', 'encrypt'] }]),
    code: 'USE_KEY_OPS_MISMATCH'
  }
];
matrix('auditJwks weak key propagation', weakKeyInSetCases, ({ build, code }) => {
  expectUnsafe(auditJwks(build()), code);
});

test('auditJwks rotation set with distinct material passes', () => {
  const report = auditJwks(publicJwks([RSA_PUBLIC, EC_PUBLIC, ED_PUBLIC]));
  assert.equal(report.counts.critical, 0);
  assert.equal(report.counts.high, 0);
});
