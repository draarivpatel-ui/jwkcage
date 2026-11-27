import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { matrix, publicJwks, RSA_PRIVATE, RSA_PUBLIC } from './helpers.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'jwkcage.mjs');

function run(args, input) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    input: input === undefined ? '' : input,
    encoding: 'utf8',
    timeout: 15000
  });
}

const rsaJson = JSON.stringify(RSA_PUBLIC);
const jwksJson = JSON.stringify(publicJwks([RSA_PUBLIC]));

test('cli version prints package version', () => {
  const result = run(['version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'jwkcage 1.0.0\n');
});

test('cli --version alias works', () => {
  assert.equal(run(['--version']).stdout, 'jwkcage 1.0.0\n');
});

test('cli help exits zero', () => {
  const result = run(['help']);
  assert.equal(result.status, 0);
  assert.ok(result.stdout.includes('audit-jwks'));
});

test('cli no arguments is a usage error', () => {
  assert.equal(run([]).status, 2);
});

test('cli unknown command is a usage error', () => {
  assert.equal(run(['frobnicate']).status, 2);
});

test('cli parse prints validated jwk', () => {
  const result = run(['parse', rsaJson]);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).kty, 'RSA');
});

test('cli parse reads stdin with dash', () => {
  const result = run(['parse', '-'], rsaJson);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).kty, 'RSA');
});

test('cli parse rejects invalid jwk with exit 1', () => {
  assert.equal(run(['parse', '{"kty":"BAD"}']).status, 1);
});

test('cli parse rejects malformed json', () => {
  assert.equal(run(['parse', '{broken']).status, 1);
});

test('cli parse missing argument is usage error', () => {
  assert.equal(run(['parse']).status, 2);
});

test('cli audit-jwk safe key exits zero', () => {
  assert.equal(run(['audit-jwk', rsaJson]).status, 0);
});

test('cli audit-jwk weak key exits 1', () => {
  const weak = { kty: 'RSA', n: RSA_PUBLIC.n, e: 'Aw' };
  assert.equal(run(['audit-jwk', JSON.stringify(weak)]).status, 1);
});

test('cli audit-jwk json mode emits structured report', () => {
  const result = run(['audit-jwk', '--json', rsaJson]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.safe, true);
  assert.ok(Array.isArray(report.findings));
});

test('cli audit-jwk private key exits 1', () => {
  assert.equal(run(['audit-jwk', JSON.stringify(RSA_PRIVATE)]).status, 1);
});

test('cli audit-jwks clean set exits zero', () => {
  assert.equal(run(['audit-jwks', jwksJson]).status, 0);
});

test('cli audit-jwks leaking set exits 1', () => {
  assert.equal(run(['audit-jwks', JSON.stringify(publicJwks([RSA_PRIVATE]))]).status, 1);
});

test('cli audit-jwks json mode reports findings array', () => {
  const result = run(['audit-jwks', '--json', JSON.stringify(publicJwks([RSA_PRIVATE]))]);
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout);
  assert.ok(report.findings.some((hit) => hit.code === 'PUBLIC_JWKS_PRIVATE_LEAK'));
});

test('cli audit-header safe header exits zero', () => {
  assert.equal(run(['audit-header', '{"alg":"RS256","kid":"a"}']).status, 0);
});

test('cli audit-header none alg exits 1', () => {
  assert.equal(run(['audit-header', '{"alg":"none"}']).status, 1);
});

test('cli audit-header None capitalized exits 1', () => {
  assert.equal(run(['audit-header', '{"alg":"None"}']).status, 1);
});

test('cli audit-header ssrf jku exits 1', () => {
  assert.equal(run(['audit-header', '{"alg":"RS256","jku":"https://169.254.169.254/x"}']).status, 1);
});

test('cli audit-header inline jwk exits 1', () => {
  assert.equal(run(['audit-header', '{"alg":"RS256","jwk":{"kty":"RSA"}}']).status, 1);
});

test('cli thumbprint matches rfc vector', () => {
  const rfc = JSON.stringify({
    kty: 'RSA',
    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    e: 'AQAB'
  });
  const result = run(['thumbprint', rfc]);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
});

test('cli thumbprint sha384 length', () => {
  assert.equal(run(['thumbprint', rsaJson, 'sha384']).stdout.trim().length, 64);
});

test('cli thumbprint rejects sha1', () => {
  assert.equal(run(['thumbprint', rsaJson, 'sha1']).status, 1);
});

test('cli strip removes private material', () => {
  const result = run(['strip', JSON.stringify(RSA_PRIVATE)]);
  assert.equal(result.status, 0);
  const key = JSON.parse(result.stdout);
  assert.equal(key.d, undefined);
  assert.notEqual(key.n, undefined);
});

test('cli select returns unique key', () => {
  const result = run(['select', jwksJson, '{"alg":"RS256","kid":"rsa-test-1"}', '--alg', 'RS256']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).kty, 'RSA');
});

test('cli select without alg flag is usage error', () => {
  assert.equal(run(['select', jwksJson, '{"alg":"RS256"}']).status, 2);
});

test('cli select with wrong kid exits 1', () => {
  assert.equal(run(['select', jwksJson, '{"alg":"RS256","kid":"nope"}', '--alg', 'RS256']).status, 1);
});

test('cli select comma separated alg list', () => {
  const result = run(['select', jwksJson, '{"alg":"RS256","kid":"rsa-test-1"}', '--alg', 'PS256,RS256']);
  assert.equal(result.status, 0);
});

test('cli select exits 1 for alg outside allowlist', () => {
  assert.equal(run(['select', jwksJson, '{"alg":"ES256","kid":"rsa-test-1"}', '--alg', 'RS256']).status, 1);
});

const usageErrorCases = [
  { name: 'audit-jwk missing arg', args: ['audit-jwk'] },
  { name: 'audit-jwks missing arg', args: ['audit-jwks'] },
  { name: 'audit-header missing arg', args: ['audit-header'] },
  { name: 'thumbprint missing arg', args: ['thumbprint'] },
  { name: 'strip missing arg', args: ['strip'] },
  { name: 'select missing args', args: ['select'] },
  { name: 'select missing header arg', args: ['select', jwksJson] }
];
matrix('cli usage errors exit 2', usageErrorCases, ({ args }) => {
  assert.equal(run(args).status, 2);
});

test('cli stdin for audit-jwks', () => {
  const result = run(['audit-jwks', '-'], jwksJson);
  assert.equal(result.status, 0);
});

test('cli output never echoes private key material in errors', () => {
  const result = run(['audit-jwk', '--json', JSON.stringify(RSA_PRIVATE)]);
  assert.equal(result.stdout.includes(RSA_PRIVATE.d), false);
});
