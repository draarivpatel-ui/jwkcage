import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function cleanEnv() {
  const env = { ...process.env };
  delete env.npm_config_store_dir;
  return env;
}

function run(cmd, args) {
  return spawnSync(cmd, args, { cwd: root, encoding: 'utf8', timeout: 120000, env: cleanEnv() });
}

function runNodeScript(script, args) {
  return run(process.execPath, [script, ...args]);
}

function existingFile(candidates) {
  return candidates.find((candidate) => typeof candidate === 'string' && candidate.length > 0 && fs.existsSync(candidate));
}

function npmCommand(args) {
  if (process.platform === 'win32') {
    const nodeRoot = path.dirname(process.execPath);
    const npmCli = existingFile([
      process.env.npm_execpath,
      path.join(nodeRoot, 'node_modules', 'npm', 'bin', 'npm-cli.js')
    ]);
    if (npmCli === undefined) return { error: new Error('npm CLI entry point was not found'), status: null, stdout: '', stderr: '' };
    return runNodeScript(npmCli, args);
  }
  return run('npm', args);
}

const result = npmCommand(['pack', '--dry-run', '--json']);
if (result.error) {
  console.error('npm pack could not be started: ' + result.error.message);
  process.exit(1);
}
if (result.status !== 0) {
  process.stderr.write(result.stdout + result.stderr);
  process.exit(result.status === null ? 1 : result.status);
}
const combined = result.stdout + '\n' + result.stderr;
if (/npm warn/iu.test(combined)) {
  console.error('npm pack emitted warnings');
  process.stderr.write(result.stderr);
  process.exit(1);
}
const jsonStart = result.stdout.indexOf('[');
if (jsonStart < 0) {
  console.error('npm pack did not emit JSON output');
  process.exit(1);
}
let entries;
try {
  entries = JSON.parse(result.stdout.slice(jsonStart));
} catch (error) {
  console.error('npm pack JSON could not be parsed: ' + error.message);
  process.exit(1);
}
if (!Array.isArray(entries) || entries.length !== 1) {
  console.error('npm pack JSON did not describe exactly one package');
  process.exit(1);
}
const info = entries[0];
if (info.name !== 'jwkcage' || info.version !== '1.0.0') {
  console.error('npm package identity mismatch');
  process.exit(1);
}
const files = new Set(info.files.map((file) => file.path));
const required = [
  'package.json',
  'README.md',
  'LICENSE',
  'SECURITY.md',
  'CONTRIBUTING.md',
  'CHANGELOG.md',
  'bin/jwkcage.mjs',
  'src/index.mjs',
  'dist/cjs/index.cjs',
  'types/index.d.ts',
  'examples/audit-public-jwks.mjs',
  'examples/verify-token-keys.mjs',
  'examples/header-threat-scan.mjs'
];
const missing = required.filter((file) => !files.has(file));
if (missing.length > 0) {
  console.error('npm package is missing: ' + missing.join(', '));
  process.exit(1);
}
const forbidden = [...files].filter((file) => file.startsWith('test/') || file.startsWith('scripts/') || file.startsWith('.github/') || file.startsWith('node_modules/') || file.endsWith('.tgz') || file === '.gitignore' || file === '.gitattributes');
if (forbidden.length > 0) {
  console.error('npm package contains development files: ' + forbidden.join(', '));
  process.exit(1);
}
const bin = info.files.find((file) => file.path === 'bin/jwkcage.mjs');
if (!bin || (bin.mode & 0o111) === 0) {
  console.error('bin/jwkcage.mjs is not executable in the package');
  process.exit(1);
}
process.stdout.write('npm package contents are correct with zero npm warnings\n');
