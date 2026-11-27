import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'jwkcage.mjs');
const rsaPublic = JSON.stringify({
  kty: 'RSA',
  n: 'qS8LtpU9ZPCikjq9IU_uA-DNFh96zsm5ETOQSpHtlTesZ_ppEc-QC7vzqHCZSN6C82aMqUTmlQ63Zrhrk2is63Cv2Usm3vRD4GIBrQW6dUXas8jG13b7y2M4T4emmT07Aad2-QOxblcid9gPhqXy-MU3iFA0beaULD-WGefvjo0zkzpXfvC-6MrpMon-PFJq3qY8-I4rtSYNDE7JEqAOvKc60ZU6WYcLMfmvxs5ja2A-2PfoeIx99f6wWY2lSsFdHedx4sktkfhhhcX2_641r-ex9ZMQ20SV-ee4kkQVO4iRaHPCroGSJVmFHvRD688qf2u75PxhDAx0Kqg7VtmMeQ',
  e: 'AQAB',
  alg: 'RS256',
  kid: 'rsa-test-1'
});
const jwks = JSON.stringify({ keys: [JSON.parse(rsaPublic)] });

function run(args, input = '') {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, input, encoding: 'utf8', timeout: 10000 });
}

assert.equal(run(['--version']).stdout, 'jwkcage 1.0.0\n');
assert.equal(run(['parse', rsaPublic]).status, 0);
assert.equal(run(['parse', '-'], rsaPublic).status, 0);
assert.equal(run(['parse', '{"kty":"BAD"}']).status, 1);
assert.equal(run(['audit-jwk', rsaPublic]).status, 0);
assert.equal(run(['audit-jwk', '{"kty":"RSA","n":"' + 'gAAAAA' + '","e":"Aw"}']).status, 1);
assert.equal(run(['audit-jwks', jwks]).status, 0);
assert.equal(run(['audit-header', '{"alg":"RS256","kid":"a"}']).status, 0);
assert.equal(run(['audit-header', '{"alg":"none"}']).status, 1);
assert.equal(run(['audit-header', '{"alg":"None"}']).status, 1);
assert.equal(run(['audit-header', '{"alg":"RS256","jku":"https://127.0.0.1/x"}']).status, 1);
assert.equal(run(['thumbprint', rsaPublic]).status, 0);
assert.equal(run(['strip', rsaPublic]).status, 0);
assert.equal(run(['select', jwks, '{"alg":"RS256","kid":"rsa-test-1"}', '--alg', 'RS256']).status, 0);
assert.equal(run(['select', jwks, '{"alg":"RS256"}']).status, 2);
assert.equal(run(['does-not-exist']).status, 2);
process.stdout.write('jwkcage CLI smoke passed\n');
