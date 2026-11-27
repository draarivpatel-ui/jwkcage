import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditEndpointUrl,
  auditJwk,
  auditJwtHeader,
  parseJwk
} from '../src/index.mjs';

const RSA_PUBLIC = {
  kty: 'RSA',
  n: 'qS8LtpU9ZPCikjq9IU_uA-DNFh96zsm5ETOQSpHtlTesZ_ppEc-QC7vzqHCZSN6C82aMqUTmlQ63Zrhrk2is63Cv2Usm3vRD4GIBrQW6dUXas8jG13b7y2M4T4emmT07Aad2-QOxblcid9gPhqXy-MU3iFA0beaULD-WGefvjo0zkzpXfvC-6MrpMon-PFJq3qY8-I4rtSYNDE7JEqAOvKc60ZU6WYcLMfmvxs5ja2A-2PfoeIx99f6wWY2lSsFdHedx4sktkfhhhcX2_641r-ex9ZMQ20SV-ee4kkQVO4iRaHPCroGSJVmFHvRD688qf2u75PxhDAx0Kqg7VtmMeQ',
  e: 'AQAB',
  alg: 'RS256',
  use: 'sig',
  kid: 'rsa-test-1'
};
const EC_PUBLIC = {
  kty: 'EC',
  crv: 'P-256',
  x: 'S-9aV0QIqaT8Epgpifg_Py5oennvh1xkWYicAldZCZ8',
  y: '7JMwOharzFE2SMiPhEObwyAL-nInqjhUzzWt7_8VuuM',
  alg: 'ES256',
  use: 'sig',
  kid: 'ec-test-1'
};
const clone = (value) => JSON.parse(JSON.stringify(value));
const codes = (report) => new Set(report.findings.map((hit) => hit.code));


test('redteam auditJwk reports one audited key even when clean', () => {
  const report = auditJwk(clone(RSA_PUBLIC));
  assert.equal(report.safe, true);
  assert.equal(report.keysAudited, 1);
});


test('redteam non-canonical base64url pad bits are rejected', () => {
  const key = { kty: 'oct', k: 'AR' };
  assert.throws(() => parseJwk(key), /JWKCAGE_INVALID_BASE64URL/u);
});

test('redteam maxFindings truncation remains fail closed when warnings precede criticals', () => {
  const key = { kty: 'oct', k: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef', alg: 'none' };
  const report = auditJwk(key, { bounds: { maxFindings: 1 } });
  assert.equal(report.counts.critical + report.counts.high > 0, true);
  assert.equal(report.safe, false);
  assert.equal(report.truncated, true);
});

test('redteam jwt header truncation remains fail closed', () => {
  const report = auditJwtHeader({ alg: 'none', kid: '../x', jku: 'https://127.0.0.1/x' }, { bounds: { maxFindings: 1 } });
  assert.equal(report.counts.critical + report.counts.high > 0, true);
  assert.equal(report.safe, false);
});

test('redteam pretty printed strict JSON input parses', () => {
  const text = '{\n  "kty": "RSA",\n  "n": "' + RSA_PUBLIC.n + '",\n  "e": "AQAB"\n}';
  assert.equal(parseJwk(text).kty, 'RSA');
  assert.equal(auditJwk(text).safe, true);
});

test('redteam object input rejects non-enumerable pollution keys', () => {
  const key = clone(RSA_PUBLIC);
  Object.defineProperty(key, '__proto__', { value: {}, enumerable: false });
  const report = auditJwk(key);
  assert.equal(report.safe, false);
});

test('redteam object input rejects accessors cycles and non-json values', () => {
  const getter = {};
  Object.defineProperty(getter, 'kty', { get: () => 'RSA' });
  assert.equal(auditJwk(getter).safe, false);
  const cyclic = clone(RSA_PUBLIC);
  cyclic.self = cyclic;
  assert.equal(auditJwk(cyclic).safe, false);
  const fn = { ...clone(RSA_PUBLIC), extension: () => 1 };
  assert.equal(auditJwk(fn).safe, false);
});

test('redteam ec coordinates must be in field and on curve', () => {
  const outOfRange = { ...clone(EC_PUBLIC), x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
  assert.equal(auditJwk(outOfRange).safe, false);
  assert.throws(() => parseJwk(outOfRange), /JWKCAGE_INVALID_EC_PARAMETERS/u);
  const offCurve = { ...clone(EC_PUBLIC), y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB' };
  assert.equal(auditJwk(offCurve).safe, false);
  assert.throws(() => parseJwk(offCurve), /JWKCAGE_INVALID_EC_PARAMETERS/u);
});

test('redteam alg curve mismatch is critical', () => {
  const report = auditJwk({ ...clone(EC_PUBLIC), alg: 'ES384' });
  assert.equal(codes(report).has('ALG_CURVE_MISMATCH'), true);
  assert.equal(report.safe, false);
});

test('redteam report endpoint trailing dot hosts are flagged', () => {
  for (const url of ['https://localhost./keys', 'https://127.0.0.1./keys']) {
    const findings = auditEndpointUrl(url, 'jku');
    const list = new Set(findings.map((hit) => hit.code));
    assert.equal(list.has('ENDPOINT_URL_TRAILING_DOT'), true);
    assert.equal(list.has('ENDPOINT_URL_INTERNAL_HOST') || list.has('ENDPOINT_URL_IP_NOT_PUBLIC'), true);
  }
});

test('redteam backslash url confusion is canonically analyzed', () => {
  const findings = auditEndpointUrl('https://127.0.0.1\\@evil.example/keys', 'jku');
  const list = new Set(findings.map((hit) => hit.code));
  assert.equal(list.has('ENDPOINT_URL_BACKSLASH_CONFUSION') || list.has('ENDPOINT_URL_IP_NOT_PUBLIC'), true);
  assert.equal(list.has('ENDPOINT_URL_IP_NOT_PUBLIC'), true);
});
