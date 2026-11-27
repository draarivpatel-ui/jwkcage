import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const typesPath = path.join(root, 'types', 'index.d.ts');
const tsconfigPath = path.join(root, 'test', 'tsconfig.json');
const declaration = fs.readFileSync(typesPath, 'utf8');

if (/\bany\b/u.test(declaration)) {
  console.error('types/index.d.ts must not use the any type');
  process.exit(1);
}
for (const required of ['parseJwk', 'auditJwk', 'auditJwks', 'auditJwtHeader', 'selectVerificationKey', 'stripPrivateMaterial', 'computeJwkThumbprint']) {
  if (!declaration.includes('function ' + required + '(')) {
    console.error('types/index.d.ts does not declare ' + required);
    process.exit(1);
  }
}

function run(cmd, args) {
  return spawnSync(cmd, args, {
    cwd: root,
    encoding: 'utf8',
    timeout: 120000
  });
}

function runNodeScript(script, args) {
  return run(process.execPath, [script, ...args]);
}

function existingFile(candidates) {
  return candidates.find((candidate) => typeof candidate === 'string' && candidate.length > 0 && fs.existsSync(candidate));
}

function windowsNpmCli() {
  const nodeRoot = path.dirname(process.execPath);
  return existingFile([
    process.env.npm_execpath,
    path.join(nodeRoot, 'node_modules', 'npm', 'bin', 'npm-cli.js')
  ]);
}

function npmTypeCheck() {
  const args = ['exec', '--yes', '--package=typescript@5.9.2', '--', 'tsc', '-p', tsconfigPath, '--pretty', 'false'];
  if (process.platform === 'win32') {
    const npmCli = windowsNpmCli();
    if (npmCli !== undefined) return runNodeScript(npmCli, args);
    return { error: new Error('npm CLI entry point was not found'), status: null, stdout: '', stderr: '' };
  }
  return run('npm', args);
}

let result = null;
if (process.platform === 'win32') {
  const nodeRoot = path.dirname(process.execPath);
  const tscCli = existingFile([
    path.join(nodeRoot, 'node_modules', 'typescript', 'bin', 'tsc')
  ]);
  result = tscCli === undefined ? npmTypeCheck() : runNodeScript(tscCli, ['-p', tsconfigPath, '--pretty', 'false']);
} else {
  result = run('tsc', ['-p', tsconfigPath, '--pretty', 'false']);
  if (result.error && result.error.code === 'ENOENT') {
    const fallback = npmTypeCheck();
    if (!fallback.error || fallback.error.code !== 'ENOENT') result = fallback;
  }
}
if (result.error) {
  console.error('type checker could not be started: ' + result.error.message);
  process.exit(1);
}
if (result.status !== 0) {
  process.stderr.write(result.stdout + result.stderr);
  process.exit(result.status === null ? 1 : result.status);
}
process.stdout.write('strict TypeScript declaration check passed\n');
