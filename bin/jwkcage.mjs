#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import {
  auditJwk,
  auditJwks,
  auditJwtHeader,
  computeJwkThumbprint,
  JWKCAGE_VERSION,
  parseJwk,
  selectVerificationKey,
  stripPrivateMaterial
} from '../src/index.mjs';

const USAGE = `jwkcage ${JWKCAGE_VERSION}

Usage: jwkcage <command> [options]

Commands:
  parse <jwk-json|->                 Strictly parse and validate one JWK
  audit-jwk <jwk-json|->             Audit one JWK for weak keys and misuse
  audit-jwks <jwks-json|->           Audit a public JWKS for leaks, collisions, weak keys
  audit-header <header-json|->       Audit a JWS or JWE header for injection and confusion
  thumbprint <jwk-json|-> [hash]     Compute the RFC 7638 thumbprint (sha256, sha384, sha512)
  strip <jwk-json|->                 Remove private key material and print the public JWK
  select <jwks-json|-> <header-json> Select the unique verification key (needs --alg)
  version                            Print the version
  help                               Print this help

Options:
  --json            Emit machine-readable JSON for audit commands
  --alg <list>      Comma-separated algorithm allowlist for select
  --allow-symmetric  Permit HMAC keys in select (off by default)
  -                 Pass - as the JSON argument to read from standard input

Exit codes: 0 success or safe, 1 unsafe or invalid input, 2 usage error.
`;

function readInput(arg) {
  if (arg === '-') {
    return readFileSync(0, 'utf8');
  }
  return arg;
}

function emit(report, jsonMode) {
  if (jsonMode) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write((report.safe ? 'safe' : 'unsafe') + '\n');
    for (const hit of report.findings) {
      process.stdout.write(hit.severity + ' ' + hit.code + ' ' + hit.field + ': ' + hit.message + '\n');
    }
  }
}

function main(argv) {
  const args = [...argv];
  const jsonMode = args.includes('--json');
  const algIndex = args.indexOf('--alg');
  let algorithms;
  if (algIndex !== -1) {
    const value = args[algIndex + 1];
    if (value === undefined) {
      process.stderr.write('missing value for --alg\n');
      return 2;
    }
    algorithms = value.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0);
    args.splice(algIndex, 2);
  }
  const allowSymmetric = args.includes('--allow-symmetric');
  for (const flag of ['--json', '--allow-symmetric']) {
    let at;
    while ((at = args.indexOf(flag)) !== -1) args.splice(at, 1);
  }
  const command = args[0];
  if (command === 'version' || command === '--version' || command === '-v') {
    process.stdout.write('jwkcage ' + JWKCAGE_VERSION + '\n');
    return 0;
  }
  if (command === 'help' || command === '--help' || command === '-h' || command === undefined) {
    process.stdout.write(USAGE);
    return command === undefined ? 2 : 0;
  }
  try {
    if (command === 'parse') {
      const input = args[1];
      if (input === undefined) return usageError('parse needs a JWK JSON argument');
      const parsed = parseJwk(readInput(input));
      process.stdout.write(JSON.stringify(parsed, null, 2) + '\n');
      return 0;
    }
    if (command === 'audit-jwk' || command === 'audit-jwks' || command === 'audit-header') {
      const input = args[1];
      if (input === undefined) return usageError(command + ' needs a JSON argument');
      const report = command === 'audit-jwk'
        ? auditJwk(readInput(input))
        : command === 'audit-jwks'
          ? auditJwks(readInput(input))
          : auditJwtHeader(readInput(input));
      emit(report, jsonMode);
      return report.safe ? 0 : 1;
    }
    if (command === 'thumbprint') {
      const input = args[1];
      if (input === undefined) return usageError('thumbprint needs a JWK JSON argument');
      const hash = args[2];
      process.stdout.write(computeJwkThumbprint(readInput(input), hash) + '\n');
      return 0;
    }
    if (command === 'strip') {
      const input = args[1];
      if (input === undefined) return usageError('strip needs a JWK JSON argument');
      process.stdout.write(JSON.stringify(stripPrivateMaterial(readInput(input)), null, 2) + '\n');
      return 0;
    }
    if (command === 'select') {
      const jwks = args[1];
      const header = args[2];
      if (jwks === undefined || header === undefined) return usageError('select needs JWKS and header JSON arguments');
      if (algorithms === undefined || algorithms.length === 0) return usageError('select needs --alg with an explicit allowlist');
      const options = { algorithms };
      if (allowSymmetric) options.allowSymmetric = true;
      const key = selectVerificationKey(readInput(jwks), readInput(header), options);
      process.stdout.write(JSON.stringify(key, null, 2) + '\n');
      return 0;
    }
    process.stderr.write('unknown command: ' + String(command) + '\n');
    return 2;
  } catch (error) {
    process.stderr.write((error && error.message ? error.message : String(error)) + '\n');
    return 1;
  }
}

function usageError(message) {
  process.stderr.write(message + '\n');
  return 2;
}

process.exitCode = main(process.argv.slice(2));
