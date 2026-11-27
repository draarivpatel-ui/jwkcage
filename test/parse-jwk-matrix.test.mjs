import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isJwkCageError, parseJwk } from '../src/index.mjs';
import { cloneKey, EC_PUBLIC, ED_PUBLIC, matrix, OCT_KEY, RSA_PRIVATE, RSA_PUBLIC } from './helpers.mjs';

function expectParseError(input, code) {
  assert.throws(
    () => parseJwk(input),
    (error) => {
      assert.ok(isJwkCageError(error), 'expected a JwkCageError, got: ' + error);
      if (code !== undefined) assert.equal(error.code, code, 'wrong error code: ' + error.message);
      return true;
    }
  );
}

const validCases = [
  { name: 'rsa public object', input: RSA_PUBLIC },
  { name: 'rsa private object', input: RSA_PRIVATE },
  { name: 'ec public object', input: EC_PUBLIC },
  { name: 'ed25519 public object', input: ED_PUBLIC },
  { name: 'oct key object', input: OCT_KEY },
  { name: 'rsa json string', input: JSON.stringify(RSA_PUBLIC) },
  { name: 'ec json string', input: JSON.stringify(EC_PUBLIC) },
  { name: 'minimal rsa', input: { kty: 'RSA', n: RSA_PUBLIC.n, e: RSA_PUBLIC.e } },
  { name: 'minimal ec', input: { kty: 'EC', crv: 'P-256', x: EC_PUBLIC.x, y: EC_PUBLIC.y } },
  { name: 'minimal okp', input: { kty: 'OKP', crv: 'Ed25519', x: ED_PUBLIC.x } },
  { name: 'minimal oct', input: { kty: 'oct', k: OCT_KEY.k } },
  { name: 'p384 curve', input: { kty: 'EC', crv: 'P-384', x: 'B' + 'A'.repeat(63), y: 'B' + 'A'.repeat(63) } },
  { name: 'p521 curve', input: { kty: 'EC', crv: 'P-521', x: 'B' + 'A'.repeat(87), y: 'B' + 'A'.repeat(87) } },
  { name: 'ed448 curve', input: { kty: 'OKP', crv: 'Ed448', x: 'B' + 'A'.repeat(75) } },
  { name: 'x25519 curve', input: { kty: 'OKP', crv: 'X25519', x: 'B' + 'A'.repeat(42) } },
  { name: 'x448 curve', input: { kty: 'OKP', crv: 'X448', x: 'B' + 'A'.repeat(74) } },
  { name: 'use sig', input: { ...cloneKey(RSA_PUBLIC), use: 'sig' } },
  { name: 'use enc', input: { ...cloneKey(RSA_PUBLIC), use: 'enc' } },
  { name: 'key_ops verify', input: { ...cloneKey(RSA_PUBLIC), key_ops: ['verify'] } },
  { name: 'key_ops multi', input: { ...cloneKey(RSA_PUBLIC), key_ops: ['sign', 'verify'] } },
  { name: 'key_ops encrypt family', input: { ...cloneKey(RSA_PUBLIC), use: 'enc', key_ops: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'] } },
  { name: 'extension member preserved', input: { ...cloneKey(RSA_PUBLIC), 'x-custom': { nested: [1, 2, 3] } } },
  { name: 'kid unicode', input: { ...cloneKey(RSA_PUBLIC), kid: 'key-2024' } },
  { name: 'x5c chain', input: { ...cloneKey(RSA_PUBLIC), x5c: ['MIIB'] } },
  { name: 'x5t present', input: { ...cloneKey(RSA_PUBLIC), x5t: 'abc123' } },
  { name: 'null prototype object input', input: Object.assign(Object.create(null), cloneKey(RSA_PUBLIC)) }
];

matrix('parseJwk valid', validCases, ({ input }) => {
  const parsed = parseJwk(input);
  assert.equal(typeof parsed, 'object');
  assert.ok(Object.isFrozen(parsed), 'parsed key must be frozen');
});

const invalidShapes = [
  { name: 'null', input: null },
  { name: 'undefined', input: undefined },
  { name: 'number', input: 42 },
  { name: 'boolean', input: true },
  { name: 'array', input: [] },
  { name: 'array of key', input: [RSA_PUBLIC] },
  { name: 'empty string', input: '' },
  { name: 'non-json string', input: 'not json' },
  { name: 'json array string', input: '[]' },
  { name: 'json number string', input: '42' },
  { name: 'json null string', input: 'null' },
  { name: 'json string string', input: '"x"' },
  { name: 'empty object', input: {} },
  { name: 'object without kty', input: { n: 'x', e: 'y' } },
  { name: 'kty wrong case rsa', input: { ...cloneKey(RSA_PUBLIC), kty: 'rsa' } },
  { name: 'kty number', input: { kty: 5 } },
  { name: 'kty null', input: { kty: null } },
  { name: 'kty empty', input: { kty: '' } },
  { name: 'kty unknown', input: { kty: 'AES' } },
  { name: 'kty whitespace', input: { kty: 'RSA ' } },
  { name: 'trailing json garbage', input: JSON.stringify(RSA_PUBLIC) + ' x' },
  { name: 'leading whitespace json ok but trailing comma', input: '{"kty":"RSA",}' },
  { name: 'single quotes json', input: "{'kty':'RSA'}" },
  { name: 'unquoted keys json', input: '{kty:"RSA"}' },
  { name: 'nan json', input: '{"kty":"RSA","n":NaN}' },
  { name: 'infinity json', input: '{"kty":"RSA","n":Infinity}' },
  { name: 'hex number json', input: '{"kty":"RSA","n":0x10}' },
  { name: 'leading zero number', input: '{"kty":"RSA","n":01}' },
  { name: 'plus number', input: '{"kty":"RSA","n":+1}' },
  { name: 'bare fraction', input: '{"kty":"RSA","n":.5}' },
  { name: 'comment json', input: '{"kty":"RSA"/*x*/}' }
];

matrix('parseJwk rejects malformed input', invalidShapes, ({ input }) => {
  expectParseError(input);
});

const rsaBreaks = [];
for (const [field, mutate, label] of [
  ['n', () => undefined, 'missing n'],
  ['e', () => undefined, 'missing e'],
  ['n', () => '', 'empty n'],
  ['e', () => '', 'empty e'],
  ['n', () => 'not base64!!', 'n bad charset'],
  ['e', () => 'AQ=A', 'e embedded padding'],
  ['n', () => 'A', 'n length mod 4 is 1'],
  ['e', () => 65537, 'e numeric'],
  ['n', () => null, 'n null'],
  ['n', () => ['AQAB'], 'n array'],
  ['n', () => 'AA', 'n leading zero byte'],
  ['e', () => 'AAE', 'e leading zero byte']
]) {
  rsaBreaks.push({
    name: 'rsa ' + label,
    build() {
      const key = cloneKey(RSA_PUBLIC);
      if (mutate() === undefined) delete key[field];
      else key[field] = mutate();
      return key;
    }
  });
}
rsaBreaks.push({
  name: 'rsa even modulus',
  build() {
    const key = cloneKey(RSA_PUBLIC);
    key.n = 'g' + key.n.slice(1);
    const bytes = Buffer.from(key.n, 'base64url');
    bytes[bytes.length - 1] = bytes[bytes.length - 1] & 0xfe;
    key.n = bytes.toString('base64url');
    return key;
  }
});
rsaBreaks.push({
  name: 'rsa p without q',
  build() {
    const key = cloneKey(RSA_PRIVATE);
    delete key.q;
    return key;
  }
});
rsaBreaks.push({
  name: 'rsa q without p',
  build() {
    const key = cloneKey(RSA_PRIVATE);
    delete key.p;
    return key;
  }
});
rsaBreaks.push({
  name: 'rsa crt without p q',
  build() {
    const key = cloneKey(RSA_PUBLIC);
    key.d = RSA_PRIVATE.d;
    key.dp = RSA_PRIVATE.dp;
    return key;
  }
});
rsaBreaks.push({
  name: 'rsa oth not array',
  build() {
    const key = cloneKey(RSA_PRIVATE);
    key.oth = 'x';
    return key;
  }
});
rsaBreaks.push({
  name: 'rsa oth entry not object',
  build() {
    const key = cloneKey(RSA_PRIVATE);
    key.oth = ['x'];
    return key;
  }
});
rsaBreaks.push({
  name: 'rsa oth missing r',
  build() {
    const key = cloneKey(RSA_PRIVATE);
    key.oth = [{ d: 'AQ', t: 'AQ' }];
    return key;
  }
});

matrix('parseJwk rejects broken RSA', rsaBreaks, ({ build }) => {
  expectParseError(build());
});

const ecBreaks = [];
for (const [label, mutate] of [
  ['missing crv', (key) => { delete key.crv; }],
  ['missing x', (key) => { delete key.x; }],
  ['missing y', (key) => { delete key.y; }],
  ['unknown curve', (key) => { key.crv = 'P-192'; }],
  ['secp256k1 curve', (key) => { key.crv = 'secp256k1'; }],
  ['x wrong length', (key) => { key.x = 'AQ'; }],
  ['y wrong length', (key) => { key.y = 'AQID'; }],
  ['d wrong length', (key) => { key.d = 'AQ'; }],
  ['crv non string', (key) => { key.crv = 7; }],
  ['x non string', (key) => { key.x = 7; }],
  ['zero point', (key) => { key.x = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; key.y = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; }]
]) {
  ecBreaks.push({
    name: 'ec ' + label,
    build() {
      const key = cloneKey(EC_PUBLIC);
      mutate(key);
      return key;
    }
  });
}

matrix('parseJwk rejects broken EC', ecBreaks, ({ build }) => {
  expectParseError(build());
});

const okpBreaks = [];
for (const [label, mutate] of [
  ['missing crv', (key) => { delete key.crv; }],
  ['missing x', (key) => { delete key.x; }],
  ['unknown okp curve', (key) => { key.crv = 'Ed521'; }],
  ['x wrong length', (key) => { key.x = 'AQ'; }],
  ['null x material', (key) => { key.x = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; }],
  ['d wrong length', (key) => { key.d = 'AQ'; }]
]) {
  okpBreaks.push({
    name: 'okp ' + label,
    build() {
      const key = cloneKey(ED_PUBLIC);
      mutate(key);
      return key;
    }
  });
}

matrix('parseJwk rejects broken OKP', okpBreaks, ({ build }) => {
  expectParseError(build());
});

const octBreaks = [];
for (const [label, mutate] of [
  ['missing k', (key) => { delete key.k; }],
  ['k bad charset', (key) => { key.k = '!!!'; }],
  ['k too short floor', (key) => { key.k = 'AQID'; }],
  ['k non string', (key) => { key.k = 42; }]
]) {
  octBreaks.push({
    name: 'oct ' + label,
    build() {
      const key = cloneKey(OCT_KEY);
      mutate(key);
      return key;
    }
  });
}

matrix('parseJwk rejects broken oct', octBreaks, ({ build }) => {
  expectParseError(build());
});

const metaBreaks = [];
for (const [label, mutate] of [
  ['use invalid', (key) => { key.use = 'both'; }],
  ['use uppercase', (key) => { key.use = 'SIG'; }],
  ['use non string', (key) => { key.use = 1; }],
  ['key_ops not array', (key) => { key.key_ops = 'verify'; }],
  ['key_ops empty array', (key) => { key.key_ops = []; }],
  ['key_ops unknown op', (key) => { key.key_ops = ['verify', 'teleport']; }],
  ['key_ops duplicate', (key) => { key.key_ops = ['verify', 'verify']; }],
  ['key_ops non string entry', (key) => { key.key_ops = [1]; }],
  ['use sig with enc only ops', (key) => { key.use = 'sig'; key.key_ops = ['encrypt']; }],
  ['use enc with sig only ops', (key) => { key.use = 'enc'; key.key_ops = ['verify']; }],
  ['kid non string', (key) => { key.kid = 42; }],
  ['alg non string', (key) => { key.alg = ['RS256']; }]
]) {
  metaBreaks.push({
    name: 'metadata ' + label,
    build() {
      const key = cloneKey(RSA_PUBLIC);
      mutate(key);
      return key;
    }
  });
}

matrix('parseJwk rejects broken metadata', metaBreaks, ({ build }) => {
  expectParseError(build());
});

const duplicateCases = [
  { name: 'duplicate kty', input: '{"kty":"RSA","kty":"EC"}' },
  { name: 'duplicate n', input: '{"kty":"RSA","n":"AA","n":"BB","e":"AQAB"}' },
  { name: 'duplicate kid', input: '{"kty":"oct","k":"' + OCT_KEY.k + '","kid":"a","kid":"b"}' },
  { name: 'duplicate nested key', input: '{"kty":"oct","k":"' + OCT_KEY.k + '","x":{"a":1,"a":2}}' },
  { name: 'duplicate in array object', input: '{"kty":"oct","k":"' + OCT_KEY.k + '","x":[{"a":1,"a":2}]}' }
];

matrix('parseJwk rejects duplicate JSON keys', duplicateCases, ({ input }) => {
  expectParseError(input, 'JWKCAGE_DUPLICATE_JSON_KEY');
});

const pollutionCases = [
  { name: 'proto top-level', input: '{"__proto__":{"polluted":true},"kty":"oct","k":"' + OCT_KEY.k + '"}' },
  { name: 'proto nested', input: '{"kty":"oct","k":"' + OCT_KEY.k + '","x":{"__proto__":{"a":1}}}' },
  { name: 'constructor key', input: '{"kty":"oct","k":"' + OCT_KEY.k + '","constructor":{"a":1}}' },
  { name: 'prototype key', input: '{"kty":"oct","k":"' + OCT_KEY.k + '","prototype":1}' },
  { name: 'proto in array object', input: '{"kty":"oct","k":"' + OCT_KEY.k + '","x":[{"__proto__":{}}]}' }
];

matrix('parseJwk rejects pollution keys', pollutionCases, ({ input }) => {
  expectParseError(input, input.includes('constructor') ? 'JWKCAGE_PROTOTYPE_POLLUTION' : 'JWKCAGE_PROTOTYPE_POLLUTION');
});

test('parseJwk rejects object input carrying proto pollution', () => {
  const evil = JSON.parse('{"kty":"oct","k":"' + OCT_KEY.k + '"}');
  Object.defineProperty(evil, '__proto__', { value: { polluted: true }, enumerable: true, configurable: true });
  assert.throws(() => parseJwk(evil), /JWKCAGE_PROTOTYPE_POLLUTION/u);
});

test('parseJwk rejects object input with constructor own key', () => {
  const evil = { kty: 'oct', k: OCT_KEY.k, constructor: { prototype: {} } };
  assert.throws(() => parseJwk(evil), /JWKCAGE_PROTOTYPE_POLLUTION/u);
});

test('parseJwk does not mutate caller object', () => {
  const input = cloneKey(RSA_PUBLIC);
  const snapshot = JSON.stringify(input);
  parseJwk(input);
  assert.equal(JSON.stringify(input), snapshot);
});

test('parseJwk json pollution does not alter Object.prototype', () => {
  assert.equal({}.polluted, undefined);
  expectParseError('{"__proto__":{"polluted":true},"kty":"oct","k":"' + OCT_KEY.k + '"}');
  assert.equal({}.polluted, undefined);
});

const boundsCases = [
  { name: 'oversized json input', build: () => '{"kty":"oct","k":"' + 'A'.repeat(20000) + '"}', options: undefined },
  { name: 'custom byte budget', build: () => JSON.stringify(RSA_PUBLIC), options: { bounds: { maxJsonBytes: 10 } } },
  { name: 'deep nesting over budget', build: () => '{"kty":"oct","k":"' + OCT_KEY.k + '","x":' + '['.repeat(30) + '1' + ']'.repeat(30) + '}', options: undefined },
  { name: 'too many members', build: () => '{"kty":"oct","k":"' + OCT_KEY.k + '",' + Array.from({ length: 130 }, (_, index) => '"m' + index + '":' + index).join(',') + '}', options: undefined }
];

matrix('parseJwk enforces budgets', boundsCases, ({ build, options }) => {
  if (options === undefined) {
    expectParseError(build());
  } else {
    assert.throws(() => parseJwk(build(), options), (error) => {
      assert.ok(isJwkCageError(error));
      return true;
    });
  }
});

test('parseJwk rejects unknown options keys', () => {
  assert.throws(() => parseJwk(RSA_PUBLIC, { bogus: 1 }), /JWKCAGE_INVALID_OPTIONS/u);
});

test('parseJwk rejects undefined option values', () => {
  assert.throws(() => parseJwk(RSA_PUBLIC, { bounds: undefined }), /JWKCAGE_INVALID_OPTIONS/u);
});

test('parseJwk rejects non-object options', () => {
  assert.throws(() => parseJwk(RSA_PUBLIC, 'x'), /JWKCAGE_INVALID_OPTIONS/u);
});

test('parseJwk rejects bound above hard limit', () => {
  assert.throws(() => parseJwk(RSA_PUBLIC, { bounds: { maxJsonBytes: 99999999 } }), /JWKCAGE_INVALID_OPTIONS/u);
});

test('parseJwk rejects zero bound', () => {
  assert.throws(() => parseJwk(RSA_PUBLIC, { bounds: { maxKeys: 0 } }), /JWKCAGE_INVALID_OPTIONS/u);
});

test('parseJwk rejects unknown bound key', () => {
  assert.throws(() => parseJwk(RSA_PUBLIC, { bounds: { maxFoo: 1 } }), /JWKCAGE_INVALID_OPTIONS/u);
});

const charsetCases = [
  { name: 'n with plus', mutate: (key) => { key.n = key.n.slice(0, 4) + '+' + key.n.slice(5); } },
  { name: 'n with slash', mutate: (key) => { key.n = key.n.slice(0, 4) + '/' + key.n.slice(5); } },
  { name: 'n with equals', mutate: (key) => { key.n = key.n + '='; } },
  { name: 'n with whitespace', mutate: (key) => { key.n = key.n.slice(0, 4) + ' ' + key.n.slice(5); } },
  { name: 'e with unicode', mutate: (key) => { key.e = 'AQAB'; } }
];

matrix('parseJwk base64url charset strictness', charsetCases.slice(0, 4), ({ mutate }) => {
  const key = cloneKey(RSA_PUBLIC);
  mutate(key);
  expectParseError(key);
});

test('parseJwk accepts symmetric key at 16 byte floor', () => {
  const key = { kty: 'oct', k: 'AAAAAAAAAAAAAAAAAAAAAA' };
  const parsed = parseJwk(key);
  assert.equal(parsed.kty, 'oct');
});

test('parseJwk returns deep frozen output', () => {
  const input = { ...cloneKey(RSA_PUBLIC), ext: { nested: [1] } };
  const parsed = parseJwk(input);
  assert.ok(Object.isFrozen(parsed.ext));
  assert.ok(Object.isFrozen(parsed.ext.nested));
});
