import assert from 'node:assert/strict';
import { test } from 'node:test';
import { auditJwtHeader } from '../src/index.mjs';
import { expectSafe, expectUnsafe, matrix } from './helpers.mjs';

const safeHeaders = [
  { name: 'minimal rs256', input: { alg: 'RS256' } },
  { name: 'rs256 with kid', input: { alg: 'RS256', kid: 'rsa-1' } },
  { name: 'rs256 typ jwt', input: { alg: 'RS256', typ: 'JWT', kid: 'rsa-1' } },
  { name: 'ps256', input: { alg: 'PS256', kid: 'rsa-1' } },
  { name: 'es256', input: { alg: 'ES256', kid: 'ec-1' } },
  { name: 'es384', input: { alg: 'ES384', kid: 'ec-2' } },
  { name: 'es512', input: { alg: 'ES512', kid: 'ec-3' } },
  { name: 'eddsa', input: { alg: 'EdDSA', kid: 'ed-1' } },
  { name: 'hs256 explicit symmetric expectation', input: { alg: 'HS256', kid: 'oct-1' }, options: { expectedKty: 'oct' } },
  { name: 'json string input', input: JSON.stringify({ alg: 'RS256', kid: 'rsa-1' }) },
  { name: 'rsa expectation met', input: { alg: 'RS256' }, options: { expectedKty: 'RSA' } },
  { name: 'ec expectation met', input: { alg: 'ES256' }, options: { expectedKty: 'EC' } },
  { name: 'okp expectation met', input: { alg: 'EdDSA' }, options: { expectedKty: 'OKP' } },
  { name: 'alg in allowlist', input: { alg: 'RS256' }, options: { algorithms: ['RS256', 'PS256'] } },
  { name: 'jku public https', input: { alg: 'RS256', jku: 'https://keys.example.com/jwks.json' } },
  { name: 'x5u public https', input: { alg: 'RS256', x5u: 'https://certs.example.com/ca.pem' } },
  { name: 'jwe rsa-oaep a256gcm', input: { alg: 'RSA-OAEP', enc: 'A256GCM' }, options: { kind: 'jwe' } },
  { name: 'jwe ecdh cbc', input: { alg: 'ECDH-ES', enc: 'A128CBC-HS256' }, options: { kind: 'jwe' } },
  { name: 'cty string', input: { alg: 'RS256', cty: 'JWT' } }
];
matrix('auditJwtHeader safe baselines', safeHeaders, ({ input, options }) => {
  expectSafe(options === undefined ? auditJwtHeader(input) : auditJwtHeader(input, options));
});

const noneCases = [
  { name: 'none lowercase', alg: 'none' },
  { name: 'none capitalized', alg: 'None' },
  { name: 'none uppercase', alg: 'NONE' },
  { name: 'none mixed case', alg: 'nOnE' },
  { name: 'none with kid', alg: 'none', extra: { kid: 'x' } },
  { name: 'none with typ', alg: 'NoNe', extra: { typ: 'JWT' } }
];
matrix('auditJwtHeader alg none forbidden', noneCases, ({ alg, extra }) => {
  expectUnsafe(auditJwtHeader({ alg, ...extra }), 'ALG_NONE');
});

const algMissingCases = [
  { name: 'empty object', input: {} },
  { name: 'kid only', input: { kid: 'x' } },
  { name: 'typ only', input: { typ: 'JWT' } },
  { name: 'alg empty string', input: { alg: '' } },
  { name: 'alg null', input: { alg: null } },
  { name: 'alg number', input: { alg: 5 } },
  { name: 'alg array', input: { alg: ['RS256'] } },
  { name: 'alg object', input: { alg: {} } }
];
matrix('auditJwtHeader alg missing or mistyped', algMissingCases, ({ input }) => {
  const report = auditJwtHeader(input);
  assert.equal(report.safe, false);
  assert.ok(report.counts.critical > 0);
});

const confusionCases = [];
for (const alg of ['HS256', 'HS384', 'HS512']) {
  for (const kty of ['RSA', 'EC', 'OKP']) {
    confusionCases.push({
      name: alg + ' confusion against ' + kty,
      input: { alg, kid: 'x' },
      options: { expectedKty: kty },
      code: 'ALGORITHM_CONFUSION'
    });
  }
}
matrix('auditJwtHeader symmetric-asymmetric confusion', confusionCases, ({ input, options, code }) => {
  expectUnsafe(auditJwtHeader(input, options), code);
});

const mismatchCases = [
  { name: 'rs256 vs ec expectation', input: { alg: 'RS256' }, kty: 'EC' },
  { name: 'rs256 vs okp expectation', input: { alg: 'RS256' }, kty: 'OKP' },
  { name: 'rs256 vs oct expectation', input: { alg: 'RS256' }, kty: 'oct' },
  { name: 'es256 vs rsa expectation', input: { alg: 'ES256' }, kty: 'RSA' },
  { name: 'eddsa vs rsa expectation', input: { alg: 'EdDSA' }, kty: 'RSA' },
  { name: 'eddsa vs ec expectation', input: { alg: 'EdDSA' }, kty: 'EC' },
  { name: 'ps256 vs ec expectation', input: { alg: 'PS256' }, kty: 'EC' },
  { name: 'rsa-oaep vs ec expectation', input: { alg: 'RSA-OAEP', enc: 'A256GCM' }, kty: 'EC' },
  { name: 'ecdh-es vs rsa expectation', input: { alg: 'ECDH-ES', enc: 'A256GCM' }, kty: 'RSA' }
];
matrix('auditJwtHeader alg kty mismatch', mismatchCases, ({ input, kty }) => {
  expectUnsafe(auditJwtHeader(input, { expectedKty: kty }), 'ALG_KTY_MISMATCH');
});

const deprecatedCases = [
  { name: 'rsa1_5 header', input: { alg: 'RSA1_5', enc: 'A256GCM' } },
  { name: 'rs1 header', input: { alg: 'RS1' } },
  { name: 'hs1 header', input: { alg: 'HS1' } }
];
matrix('auditJwtHeader deprecated algorithms', deprecatedCases, ({ input }) => {
  expectUnsafe(auditJwtHeader(input), 'ALG_DEPRECATED');
});

const unknownAlgCases = [
  { name: 'made up alg', alg: 'ZZ999' },
  { name: 'lowercase rs256', alg: 'rs256' },
  { name: 'whitespace padded', alg: ' RS256' },
  { name: 'trailing space', alg: 'RS256 ' },
  { name: 'empty-ish', alg: '-' },
  { name: 'unicode alg', alg: 'RS256«' }
];
matrix('auditJwtHeader unrecognized algorithms', unknownAlgCases, ({ alg }) => {
  expectUnsafe(auditJwtHeader({ alg }), 'ALG_UNRECOGNIZED');
});

const allowlistCases = [
  { name: 'rs256 blocked when only ps256 allowed', alg: 'RS256', allow: ['PS256'] },
  { name: 'hs256 blocked when asymmetric only', alg: 'HS256', allow: ['RS256', 'ES256'] },
  { name: 'es256 blocked when only rs family', alg: 'ES256', allow: ['RS256', 'PS256'] },
  { name: 'empty allowlist blocks all', alg: 'RS256', allow: [] }
];
matrix('auditJwtHeader algorithm allowlist', allowlistCases, ({ alg, allow }) => {
  expectUnsafe(auditJwtHeader({ alg }, { algorithms: allow }), 'ALG_NOT_ALLOWLISTED');
});

const injectionCases = [
  { name: 'inline jwk rsa', input: { alg: 'RS256', jwk: { kty: 'RSA', n: 'x', e: 'y' } }, code: 'INLINE_JWK_INJECTION' },
  { name: 'inline jwk empty', input: { alg: 'RS256', jwk: {} }, code: 'INLINE_JWK_INJECTION' },
  { name: 'inline jwk oct', input: { alg: 'HS256', jwk: { kty: 'oct', k: 'x' } }, code: 'INLINE_JWK_INJECTION' },
  { name: 'inline x5c chain', input: { alg: 'RS256', x5c: ['MIIB'] }, code: 'INLINE_X5C_INJECTION' },
  { name: 'inline x5c empty', input: { alg: 'RS256', x5c: [] }, code: 'INLINE_X5C_INJECTION' },
  { name: 'both inline jwk and x5c', input: { alg: 'RS256', jwk: {}, x5c: [] }, code: 'INLINE_JWK_INJECTION' }
];
matrix('auditJwtHeader inline key injection', injectionCases, ({ input, code }) => {
  expectUnsafe(auditJwtHeader(input), code);
});

const ssrfCases = [];
for (const [url, label, code] of [
  ['http://keys.example.com/jwks.json', 'cleartext http', 'ENDPOINT_URL_NOT_HTTPS'],
  ['https://127.0.0.1/jwks.json', 'loopback ipv4', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://127.255.255.254/jwks.json', 'loopback edge', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://10.1.2.3/jwks.json', 'rfc1918 ten', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://172.16.5.5/jwks.json', 'rfc1918 172', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://172.31.255.255/jwks.json', 'rfc1918 172 edge', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://192.168.0.1/jwks.json', 'rfc1918 192', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://169.254.169.254/latest/meta-data/iam', 'cloud metadata', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://169.254.170.23/v2/credentials', 'ecs metadata', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://100.64.0.1/jwks.json', 'cgnat', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://0.0.0.0/jwks.json', 'unspecified', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://224.0.0.2/jwks.json', 'multicast', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://240.0.0.1/jwks.json', 'reserved', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://192.0.2.1/jwks.json', 'documentation', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://198.51.100.1/jwks.json', 'documentation 2', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://203.0.113.1/jwks.json', 'documentation 3', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://2130706433/jwks.json', 'integer ip', 'ENDPOINT_URL_IPV4_OBFUSCATED'],
  ['https://0x7f000001/jwks.json', 'hex ip', 'ENDPOINT_URL_IPV4_OBFUSCATED'],
  ['https://0X7F000001/jwks.json', 'uppercase hex ip', 'ENDPOINT_URL_IPV4_OBFUSCATED'],
  ['https://0177.0.0.1/jwks.json', 'octal ip', 'ENDPOINT_URL_IPV4_OBFUSCATED'],
  ['https://127.1/jwks.json', 'shorthand two part', 'ENDPOINT_URL_IPV4_OBFUSCATED'],
  ['https://127.0.1/jwks.json', 'shorthand three part', 'ENDPOINT_URL_IPV4_OBFUSCATED'],
  ['https://localhost/jwks.json', 'localhost', 'ENDPOINT_URL_INTERNAL_HOST'],
  ['https://foo.localhost/jwks.json', 'subdomain localhost', 'ENDPOINT_URL_INTERNAL_HOST'],
  ['https://service.internal/jwks.json', 'internal tld', 'ENDPOINT_URL_INTERNAL_HOST'],
  ['https://host.local/jwks.json', 'local tld', 'ENDPOINT_URL_INTERNAL_HOST'],
  ['https://intranet/jwks.json', 'single label', 'ENDPOINT_URL_INTERNAL_HOST'],
  ['https://[::1]/jwks.json', 'ipv6 loopback', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://[fd00::5]/jwks.json', 'ipv6 ula', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://[fe80::1]/jwks.json', 'ipv6 link local', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://[::ffff:127.0.0.1]/jwks.json', 'ipv4 mapped loopback', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://[::ffff:10.0.0.1]/jwks.json', 'ipv4 mapped private', 'ENDPOINT_URL_IP_NOT_PUBLIC'],
  ['https://user@keys.example.com/jwks.json', 'userinfo', 'ENDPOINT_URL_CREDENTIALS'],
  ['https://user:pass@keys.example.com/jwks.json', 'userinfo pass', 'ENDPOINT_URL_CREDENTIALS'],
  ['ftp://keys.example.com/jwks.json', 'ftp scheme', 'ENDPOINT_URL_NOT_HTTPS'],
  ['file:///etc/passwd', 'file scheme', 'ENDPOINT_URL_NOT_HTTPS'],
  ['not a url at all', 'malformed', 'ENDPOINT_URL_MALFORMED']
]) {
  ssrfCases.push({ name: 'jku ' + label, input: { alg: 'RS256', jku: url }, code });
  ssrfCases.push({ name: 'x5u ' + label, input: { alg: 'RS256', x5u: url }, code });
}
matrix('auditJwtHeader SSRF perimeter', ssrfCases, ({ input, code }) => {
  expectUnsafe(auditJwtHeader(input), code);
});

const kidCases = [
  { name: 'path traversal', kid: '../../../etc/passwd', code: 'KID_PATH_TRAVERSAL' },
  { name: 'windows traversal', kid: '..\\..\\system32', code: 'KID_PATH_TRAVERSAL' },
  { name: 'encoded traversal', kid: '%2e%2e%2f', code: 'KID_METACHARACTERS' },
  { name: 'sqli union', kid: "1' UNION SELECT * FROM keys--", code: 'KID_SQLI_PATTERN' },
  { name: 'sqli comment', kid: "admin'--", code: 'KID_SQLI_PATTERN' },
  { name: 'nul byte', kid: 'key\0', code: 'KID_CONTROL_INJECTION' },
  { name: 'crlf', kid: 'a\r\nb', code: 'KID_CONTROL_INJECTION' },
  { name: 'shell injection', kid: 'kid; rm -rf /', code: 'KID_METACHARACTERS' },
  { name: 'overlong', kid: 'z'.repeat(300), code: 'KID_TOO_LONG' }
];
matrix('auditJwtHeader kid attacks', kidCases, ({ kid, code }) => {
  expectUnsafe(auditJwtHeader({ alg: 'RS256', kid }), code);
});

test('auditJwtHeader requireKid enforces presence', () => {
  expectUnsafe(auditJwtHeader({ alg: 'RS256' }, { requireKid: true }), 'KID_REQUIRED');
});

test('auditJwtHeader requireKid satisfied', () => {
  const report = auditJwtHeader({ alg: 'RS256', kid: 'fine' }, { requireKid: true });
  assert.ok(!report.findings.some((hit) => hit.code === 'KID_REQUIRED'));
});

const critCases = [
  { name: 'crit not array', input: { alg: 'RS256', crit: 'exp' }, code: 'CRIT_TYPE' },
  { name: 'crit missing extension', input: { alg: 'RS256', crit: ['exp'] }, code: 'CRIT_EXTENSION_MISSING' },
  { name: 'crit present unknown extension', input: { alg: 'RS256', crit: ['exp'], exp: 1 }, code: 'CRIT_UNVERIFIED_EXTENSION' },
  { name: 'crit registered alg', input: { alg: 'RS256', crit: ['alg'] }, code: 'CRIT_REGISTERED_PARAMETER' },
  { name: 'crit registered kid', input: { alg: 'RS256', crit: ['kid'], kid: 'x' }, code: 'CRIT_REGISTERED_PARAMETER' },
  { name: 'crit duplicate entry', input: { alg: 'RS256', crit: ['exp', 'exp'], exp: 1 }, code: 'CRIT_DUPLICATE' },
  { name: 'crit non string entry', input: { alg: 'RS256', crit: [5] }, code: 'CRIT_ENTRY_TYPE' }
];
matrix('auditJwtHeader crit extension handling', critCases, ({ input, code }) => {
  expectUnsafe(auditJwtHeader(input), code);
});

const jweCases = [
  { name: 'jwe missing enc', input: { alg: 'RSA-OAEP' }, code: 'ENC_MISSING' },
  { name: 'jwe weak enc', input: { alg: 'RSA-OAEP', enc: 'A128GCMX' }, code: 'ENC_UNRECOGNIZED' },
  { name: 'jwe compression', input: { alg: 'RSA-OAEP', enc: 'A256GCM', zip: 'DEF' }, code: 'ZIP_COMPRESSION_ENABLED' },
  { name: 'jwe bad zip', input: { alg: 'RSA-OAEP', enc: 'A256GCM', zip: 'GZIP' }, code: 'ZIP_UNRECOGNIZED' },
  { name: 'jwe epk untrusted', input: { alg: 'ECDH-ES', enc: 'A256GCM', epk: { kty: 'EC' } }, code: 'EPK_UNTRUSTED' },
  { name: 'pbes2 low iterations', input: { alg: 'PBES2-HS256+A128KW', enc: 'A256GCM', p2c: 1000 }, code: 'P2C_TOO_LOW' },
  { name: 'pbes2 zero iterations', input: { alg: 'PBES2-HS256+A128KW', enc: 'A256GCM', p2c: 0 }, code: 'P2C_INVALID' },
  { name: 'pbes2 negative iterations', input: { alg: 'PBES2-HS256+A128KW', enc: 'A256GCM', p2c: -5 }, code: 'P2C_INVALID' },
  { name: 'pbes2 excessive iterations', input: { alg: 'PBES2-HS256+A128KW', enc: 'A256GCM', p2c: 50000000 }, code: 'P2C_EXCESSIVE' },
  { name: 'iv bad encoding', input: { alg: 'RSA-OAEP', enc: 'A256GCM', iv: '!!!' }, code: 'IV_ENCODING' },
  { name: 'tag bad encoding', input: { alg: 'RSA-OAEP', enc: 'A256GCM', tag: '===' }, code: 'TAG_ENCODING' },
  { name: 'p2s bad encoding', input: { alg: 'PBES2-HS256+A128KW', enc: 'A256GCM', p2s: '!' }, code: 'P2S_ENCODING' }
];
matrix('auditJwtHeader JWE specifics', jweCases, ({ input, code }) => {
  const report = auditJwtHeader(input, { kind: 'jwe' });
  assert.ok(report.findings.some((hit) => hit.code === code), 'expected ' + code + ', got: ' + report.findings.map((hit) => hit.code).join(', '));
});

test('auditJwtHeader pbes2 adequate iterations pass p2c checks', () => {
  const report = auditJwtHeader({ alg: 'PBES2-HS256+A128KW', enc: 'A256GCM', p2c: 200000 }, { kind: 'jwe' });
  assert.ok(!report.findings.some((hit) => hit.code === 'P2C_TOO_LOW' || hit.code === 'P2C_INVALID'));
});

test('auditJwtHeader malformed input returns critical report', () => {
  const report = auditJwtHeader('garbage{{{');
  assert.equal(report.safe, false);
  assert.ok(report.counts.critical > 0);
});

test('auditJwtHeader duplicate json keys detected', () => {
  const report = auditJwtHeader('{"alg":"RS256","alg":"none"}');
  assert.equal(report.safe, false);
  assert.ok(report.findings.some((hit) => hit.code === 'DUPLICATE_JSON_KEY'));
});

test('auditJwtHeader proto pollution detected', () => {
  const report = auditJwtHeader('{"alg":"RS256","__proto__":{"evil":1}}');
  assert.equal(report.safe, false);
  assert.ok(report.findings.some((hit) => hit.code === 'PROTOTYPE_POLLUTION'));
});

test('auditJwtHeader alg none hidden behind duplicate key never reaches verifier', () => {
  const report = auditJwtHeader('{"alg":"none","alg":"RS256"}');
  assert.equal(report.safe, false);
});

test('auditJwtHeader report frozen', () => {
  const report = auditJwtHeader({ alg: 'RS256' });
  assert.ok(Object.isFrozen(report));
});

test('auditJwtHeader counts consistent', () => {
  const report = auditJwtHeader({ alg: 'none', kid: '../x', jku: 'http://x' });
  const total = report.counts.critical + report.counts.high + report.counts.medium + report.counts.low + report.counts.info;
  assert.equal(total, report.findings.length);
});

test('auditJwtHeader rejects unknown options', () => {
  assert.throws(() => auditJwtHeader({ alg: 'RS256' }, { bogus: true }), /JWKCAGE_INVALID_OPTIONS/u);
});
