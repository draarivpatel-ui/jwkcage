import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as esm from '../src/index.mjs';
import { RSA_PUBLIC } from './helpers.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('ESM and CJS builds export identical function surfaces', () => {
  const require = createRequire(import.meta.url);
  const cjs = require(path.join(root, 'dist', 'cjs', 'index.cjs'));
  const esmFunctions = Object.keys(esm).filter((key) => typeof esm[key] === 'function').sort();
  const cjsFunctions = Object.keys(cjs).filter((key) => typeof cjs[key] === 'function').sort();
  assert.deepEqual(cjsFunctions, esmFunctions);
});

test('ESM and CJS constants agree', () => {
  const require = createRequire(import.meta.url);
  const cjs = require(path.join(root, 'dist', 'cjs', 'index.cjs'));
  assert.equal(cjs.JWKCAGE_VERSION, esm.JWKCAGE_VERSION);
  assert.deepEqual(cjs.PRIVATE_KEY_PARAMETERS, esm.PRIVATE_KEY_PARAMETERS);
  assert.deepEqual([...cjs.DEFAULT_ALLOWED_CURVES], [...esm.DEFAULT_ALLOWED_CURVES]);
});

test('CJS parseJwk works', () => {
  const require = createRequire(import.meta.url);
  const cjs = require(path.join(root, 'dist', 'cjs', 'index.cjs'));
  const parsed = cjs.parseJwk(RSA_PUBLIC);
  assert.equal(parsed.kty, 'RSA');
});

test('CJS auditJwks works', () => {
  const require = createRequire(import.meta.url);
  const cjs = require(path.join(root, 'dist', 'cjs', 'index.cjs'));
  assert.equal(cjs.auditJwks({ keys: [RSA_PUBLIC] }).safe, true);
});

test('CJS thumbprint matches RFC vector', () => {
  const require = createRequire(import.meta.url);
  const cjs = require(path.join(root, 'dist', 'cjs', 'index.cjs'));
  const rfcKey = {
    kty: 'RSA',
    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    e: 'AQAB'
  };
  assert.equal(cjs.computeJwkThumbprint(rfcKey), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
});

test('CJS error class identity preserved', () => {
  const require = createRequire(import.meta.url);
  const cjs = require(path.join(root, 'dist', 'cjs', 'index.cjs'));
  try {
    cjs.parseJwk(null);
    assert.fail('should throw');
  } catch (error) {
    assert.ok(cjs.isJwkCageError(error));
  }
});

test('generated CJS uses LF line endings only', () => {
  const text = fs.readFileSync(path.join(root, 'dist', 'cjs', 'index.cjs'), 'utf8');
  assert.ok(!text.includes('\r'), 'CJS output must be LF normalized');
});

test('generated CJS is strict mode commonjs', () => {
  const text = fs.readFileSync(path.join(root, 'dist', 'cjs', 'index.cjs'), 'utf8');
  assert.ok(text.includes('use strict'));
  assert.ok(!text.includes('import ') || text.includes('// import'), 'no ESM import statements should survive');
});

function gitFiles() {
  const output = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'buffer' });
  return output.toString('utf8').split('\u0000').filter((entry) => entry.length > 0);
}

function trackedTextFiles() {
  let files;
  try {
    files = gitFiles();
  } catch {
    files = [];
  }
  if (files.length === 0) {
    const walk = (dir) => {
      const out = [];
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === '.git' || entry.name === 'node_modules') continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) out.push(...walk(full));
        else out.push(path.relative(root, full));
      }
      return out;
    };
    files = walk(root);
  }
  return files.filter((file) => !file.endsWith('.png') && !file.endsWith('.ico'));
}

test('repository contains no em or en dashes in tracked text files', () => {
  const offenders = [];
  for (const file of trackedTextFiles()) {
    const full = path.join(root, file);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const text = fs.readFileSync(full, 'utf8');
    if (text.includes('\u2014') || text.includes('\u2013')) offenders.push(file);
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no local user paths', () => {
  const offenders = [];
  for (const file of trackedTextFiles()) {
    const full = path.join(root, file);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const text = fs.readFileSync(full, 'utf8');
    if (text.includes('/Us' + 'ers/')) offenders.push(file);
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no personal mailbox fragments', () => {
  const offenders = [];
  const patterns = ['gmail', 'yahoo', 'outlook', 'hotmail', 'proton', 'icloud'].map((host) => host + '.' + 'com');
  patterns.push('proton' + '.' + 'me');
  for (const file of trackedTextFiles()) {
    const full = path.join(root, file);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const text = fs.readFileSync(full, 'utf8');
    for (const pattern of patterns) {
      if (text.includes(pattern)) offenders.push(file + ': ' + pattern);
    }
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no co-authorship trailer markers', () => {
  const offenders = [];
  for (const file of trackedTextFiles()) {
    const full = path.join(root, file);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    if (fs.readFileSync(full, 'utf8').includes('Co-Authored' + '-By')) offenders.push(file);
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no vendor secret prefixes', () => {
  const offenders = [];
  const patterns = ['tskey-', 'sk-', 'ghp_', 'github_pat_', 'AKIA', 'xoxb-', 'xoxp-', 'gsk_', 'nvapi-', 'tvly-', 'AIza'];
  for (const file of trackedTextFiles()) {
    if (file.includes('parity-hygiene')) continue;
    const full = path.join(root, file);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const text = fs.readFileSync(full, 'utf8');
    for (const pattern of patterns) {
      if (text.includes(pattern)) offenders.push(file + ': ' + pattern);
    }
  }
  assert.deepEqual(offenders, []);
});

test('repository text files have no ascii control bytes', () => {
  const offenders = [];
  for (const file of trackedTextFiles()) {
    const full = path.join(root, file);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const buffer = fs.readFileSync(full);
    for (const byte of buffer) {
      if (byte < 32 && byte !== 10 && byte !== 9 && byte !== 13) {
        offenders.push(file);
        break;
      }
    }
  }
  assert.deepEqual(offenders, []);
});

test('package metadata is zero dependency', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(manifest.dependencies, {});
  assert.deepEqual(manifest.devDependencies, {});
  assert.equal(manifest.name, 'jwkcage');
  assert.equal(manifest.version, '1.0.0');
});

test('package exports dual esm cjs and types', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.exports['.'].import, './src/index.mjs');
  assert.equal(manifest.exports['.'].require, './dist/cjs/index.cjs');
  assert.equal(manifest.exports['.'].types, './types/index.d.ts');
  assert.equal(manifest.engines.node, '>=18.0.0');
});

test('type declarations exist and avoid any', () => {
  const text = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
  assert.ok(!/\bany\b/u.test(text), 'declarations must not use any');
  for (const name of ['parseJwk', 'auditJwk', 'auditJwks', 'auditJwtHeader', 'selectVerificationKey', 'stripPrivateMaterial', 'computeJwkThumbprint']) {
    assert.ok(text.includes(name), name + ' missing from declarations');
  }
});

test('git author configuration is campaign identity when repository exists', () => {
  if (!fs.existsSync(path.join(root, '.git'))) return;
  const result = spawnSync('git', ['log', '--format=%an %ae %cn %ce', '-1'], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0 || result.stdout.trim() === '') return;
  assert.ok(result.stdout.includes('draarivpatel-ui'));
  assert.ok(!result.stdout.includes('aariv' + 'patel@'), 'personal identity must not appear in commits');
});
