/* JWK structural parsing, strength auditing, private-material stripping, RFC 7638 thumbprints. */
import { createHash } from 'node:crypto';
import {
  ASYMMETRIC_PRIVATE_PARAMETERS,
  CURVE_FOR_ES,
  DEFAULT_ALLOWED_CURVES,
  DEFAULT_BOUNDS,
  DEPRECATED_ALGORITHMS,
  EC_CURVE_BYTES,
  HARD_BOUNDS,
  JWKCAGE_ERROR_CODES as CODE,
  JWKCAGE_SEVERITY as SEV,
  KEY_OPS_VALUES,
  KEY_TYPES,
  MIN_OCT_BYTES,
  MIN_RSA_EXPONENT,
  MIN_RSA_MODULUS_BITS,
  OKP_CURVE_BYTES,
  PRIVATE_KEY_PARAMETERS,
  USE_VALUES
} from './constants.mjs';
import { fail, JwkCageError } from './errors.mjs';
import { parseJsonStrict, scanObjectForPollution } from './jsonparse.mjs';
import { auditEndpointUrl } from './urlsec.mjs';

const BASE64URL_RE = /^[A-Za-z0-9_-]*$/u;
const CONTROL_RE = /[\u0000-\u001f\u007f]/u;
const BIDI_RE = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/u;
const KID_FORBIDDEN_RE = /[/\\?#%@:;&=+$`'"<>|*^()[\]{}!,~]/u;

export function deepFreeze(value, seen = new Set()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key], seen);
  return value;
}

export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function isBase64url(value) {
  return typeof value === 'string' && value.length > 0 && value.length % 4 !== 1 && BASE64URL_RE.test(value);
}

export function base64urlBytes(value) {
  return Buffer.from(value, 'base64url');
}

export function base64urlBigInt(value) {
  const bytes = base64urlBytes(value);
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

export function countBits(integer) {
  let bits = 0n;
  let value = integer;
  while (value > 0n) {
    bits += 1n;
    value >>= 1n;
  }
  return Number(bits);
}

function cloneJson(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(cloneJson);
  const out = {};
  for (const key of Object.keys(value)) out[key] = cloneJson(value[key]);
  return out;
}

export function normalizeOptions(options, allowedKeys, caller) {
  if (options === undefined) return {};
  if (!isPlainObject(options)) fail(CODE.INVALID_OPTIONS, caller + ' options must be a plain object');
  for (const key of Object.keys(options)) {
    if (!allowedKeys.includes(key)) fail(CODE.INVALID_OPTIONS, caller + ' does not accept option: ' + key);
    if (options[key] === undefined) fail(CODE.INVALID_OPTIONS, caller + ' option ' + key + ' must not be undefined');
  }
  return options;
}

export function normalizeBounds(options) {
  const raw = options.bounds === undefined ? {} : options.bounds;
  if (!isPlainObject(raw)) fail(CODE.INVALID_OPTIONS, 'bounds must be a plain object');
  const out = {};
  for (const key of Object.keys(DEFAULT_BOUNDS)) {
    let value = raw[key] === undefined ? DEFAULT_BOUNDS[key] : raw[key];
    if (!Number.isSafeInteger(value) || value < 1) fail(CODE.INVALID_OPTIONS, 'bounds.' + key + ' must be a positive integer');
    if (value > HARD_BOUNDS[key]) fail(CODE.INVALID_OPTIONS, 'bounds.' + key + ' exceeds the hard limit');
    out[key] = value;
  }
  for (const key of Object.keys(raw)) {
    if (!(key in DEFAULT_BOUNDS)) fail(CODE.INVALID_OPTIONS, 'unknown bounds key: ' + key);
  }
  return out;
}

export function materializeJsonInput(input, bounds, maxDepth, caller) {
  if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > bounds.maxJsonBytes) fail(CODE.INPUT_TOO_LARGE, caller + ' JSON input exceeds the byte budget');
    if (CONTROL_RE.test(input)) fail(CODE.MALFORMED_JSON, caller + ' input contains control characters');
    const parsed = parseJsonStrict(input, maxDepth);
    if (!isPlainObject(parsed)) fail(CODE.INVALID_INPUT, caller + ' JSON input must be an object');
    return parsed;
  }
  if (!isPlainObject(input)) fail(CODE.INVALID_INPUT, caller + ' input must be a plain object or a JSON object string');
  scanObjectForPollution(input, 0, maxDepth);
  return cloneJson(input);
}

export function auditKidString(kid, maxKidLength) {
  const findings = [];
  const add = (code, severity, message) => findings.push({ code, severity, field: 'kid', message });
  if (typeof kid !== 'string') {
    add('KID_TYPE', 'critical', 'kid must be a string');
    return findings;
  }
  if (kid.length === 0) add('KID_EMPTY', 'high', 'kid is empty');
  if (kid.length > maxKidLength) add('KID_TOO_LONG', 'high', 'kid exceeds the length budget');
  if (CONTROL_RE.test(kid)) add('KID_CONTROL_INJECTION', 'critical', 'kid contains control characters enabling CRLF or NUL injection');
  if (BIDI_RE.test(kid)) add('KID_BIDI_INJECTION', 'high', 'kid contains bidirectional override characters');
  if (kid.includes('..')) add('KID_PATH_TRAVERSAL', 'critical', 'kid contains a path traversal sequence');
  if (kid.includes('/') || kid.includes('\\')) add('KID_PATH_SEPARATOR', 'critical', 'kid contains a path separator');
  if (kid.startsWith('-')) add('KID_OPTION_INJECTION', 'medium', 'kid begins with a dash and can be parsed as a CLI option');
  const lowered = kid.toLowerCase();
  if (/(union|select|insert|update|delete|drop|alter|exec)\s/u.test(lowered) || lowered.includes('--') || lowered.includes('/*') || lowered.includes('*/') || /('\s*or\s|'|;\s*)/u.test(lowered)) {
    add('KID_SQLI_PATTERN', 'critical', 'kid contains SQL injection metacharacters or keywords');
  }
  if (kid.includes('=') || kid.includes("'") || kid.includes('"') || kid.includes(';') || kid.includes('|') || kid.includes('&') || kid.includes('$') || kid.includes('`') || kid.includes('<') || kid.includes('>') || kid.includes('%') || kid.includes('#') || kid.includes('?')) {
    add('KID_METACHARACTERS', 'high', 'kid contains shell, query, or template metacharacters');
  }
  if (!/^[\x20-\x7e]*$/u.test(kid)) add('KID_NON_ASCII', 'medium', 'kid contains non-ASCII characters');
  return findings;
}

export function kidIsSafe(kid, maxKidLength) {
  return auditKidString(kid, maxKidLength).every((finding) => finding.severity !== 'critical' && finding.severity !== 'high');
}

function expectString(object, key, bounds, required) {
  const value = object[key];
  if (value === undefined) {
    if (required) fail(CODE.INVALID_JWK, 'missing required member: ' + key, { field: key });
    return undefined;
  }
  if (typeof value !== 'string') fail(CODE.INVALID_JWK, key + ' must be a string', { field: key });
  if (value.length > bounds.maxStringLength) fail(CODE.INVALID_JWK, key + ' exceeds the string length budget', { field: key });
  return value;
}

function expectBase64url(object, key, required) {
  const value = object[key];
  if (value === undefined) {
    if (required) fail(CODE.INVALID_JWK, 'missing required member: ' + key, { field: key });
    return undefined;
  }
  if (!isBase64url(value)) fail(CODE.INVALID_BASE64URL, key + ' is not valid unpadded base64url', { field: key });
  return value;
}

function validateUseAndKeyOps(key, errorCode) {
  if (key.use !== undefined && !USE_VALUES.includes(key.use)) {
    fail(CODE.INVALID_USE, 'use must be sig or enc', { field: 'use' });
  }
  if (key.key_ops !== undefined) {
    if (!Array.isArray(key.key_ops)) fail(CODE.INVALID_KEY_OPS, 'key_ops must be an array', { field: 'key_ops' });
    if (key.key_ops.length === 0) fail(CODE.INVALID_KEY_OPS, 'key_ops must not be empty', { field: 'key_ops' });
    if (key.key_ops.length > KEY_OPS_VALUES.length) fail(CODE.INVALID_KEY_OPS, 'key_ops exceeds the operation budget', { field: 'key_ops' });
    const seen = new Set();
    for (const op of key.key_ops) {
      if (typeof op !== 'string' || !KEY_OPS_VALUES.includes(op)) fail(CODE.INVALID_KEY_OPS, 'key_ops contains an unrecognized operation', { field: 'key_ops' });
      if (seen.has(op)) fail(CODE.INVALID_KEY_OPS, 'key_ops contains a duplicate operation', { field: 'key_ops' });
      seen.add(op);
    }
    if (key.use !== undefined) {
      const signing = new Set(['sign', 'verify']);
      const encryption = new Set(['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
      const hasSig = key.key_ops.some((op) => signing.has(op));
      const hasEnc = key.key_ops.some((op) => encryption.has(op));
      if (key.use === 'sig' && hasEnc && !hasSig) fail(CODE.KEY_USE_MISMATCH, 'use sig conflicts with encryption-only key_ops', { field: 'key_ops' });
      if (key.use === 'enc' && hasSig && !hasEnc) fail(CODE.KEY_USE_MISMATCH, 'use enc conflicts with signing-only key_ops', { field: 'key_ops' });
    }
  }
  if (errorCode) {
    // reserved for future per-family enforcement
  }
}

function validateRsa(key, bounds) {
  expectBase64url(key, 'n', true);
  expectBase64url(key, 'e', true);
  for (const param of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expectBase64url(key, param, false);
  if (key.oth !== undefined) {
    if (!Array.isArray(key.oth)) fail(CODE.INVALID_RSA_PARAMETERS, 'oth must be an array', { field: 'oth' });
    for (const prime of key.oth) {
      if (!isPlainObject(prime)) fail(CODE.INVALID_RSA_PARAMETERS, 'oth entries must be objects', { field: 'oth' });
      for (const member of ['r', 'd', 't']) {
        if (!isBase64url(prime[member])) fail(CODE.INVALID_RSA_PARAMETERS, 'oth.' + member + ' is not valid base64url', { field: 'oth' });
      }
    }
  }
  const modulusBytes = base64urlBytes(key.n);
  if (modulusBytes.length === 0) fail(CODE.INVALID_RSA_PARAMETERS, 'RSA modulus is empty', { field: 'n' });
  if (modulusBytes[0] === 0) fail(CODE.INVALID_RSA_PARAMETERS, 'RSA modulus is not minimally encoded', { field: 'n' });
  const exponentBytes = base64urlBytes(key.e);
  if (exponentBytes.length === 0) fail(CODE.INVALID_RSA_PARAMETERS, 'RSA exponent is empty', { field: 'e' });
  if (exponentBytes[0] === 0) fail(CODE.INVALID_RSA_PARAMETERS, 'RSA exponent is not minimally encoded', { field: 'e' });
  const modulus = base64urlBigInt(key.n);
  if (modulus % 2n === 0n) fail(CODE.INVALID_RSA_PARAMETERS, 'RSA modulus is even and cannot be a valid semiprime', { field: 'n' });
  if (key.d !== undefined && (key.p === undefined) !== (key.q === undefined)) {
    fail(CODE.INVALID_RSA_PARAMETERS, 'p and q must appear together in a private RSA key', { field: 'p' });
  }
  if ((key.dp !== undefined || key.dq !== undefined || key.qi !== undefined) && (key.p === undefined || key.q === undefined || key.d === undefined)) {
    fail(CODE.INVALID_RSA_PARAMETERS, 'CRT parameters require d, p, and q', { field: 'dp' });
  }
  return { modulus, exponent: base64urlBigInt(key.e), modulusBits: countBits(modulus) };
}

function validateEc(key) {
  const crv = expectString(key, 'crv', { maxStringLength: 64 }, true);
  expectBase64url(key, 'x', true);
  expectBase64url(key, 'y', true);
  expectBase64url(key, 'd', false);
  if (!(crv in EC_CURVE_BYTES)) fail(CODE.INVALID_CURVE, 'unrecognized EC curve: ' + crv, { field: 'crv' });
  const size = EC_CURVE_BYTES[crv];
  if (base64urlBytes(key.x).length !== size) fail(CODE.INVALID_EC_PARAMETERS, 'x coordinate length does not match ' + crv, { field: 'x' });
  if (base64urlBytes(key.y).length !== size) fail(CODE.INVALID_EC_PARAMETERS, 'y coordinate length does not match ' + crv, { field: 'y' });
  if (key.d !== undefined && base64urlBytes(key.d).length !== size) fail(CODE.INVALID_EC_PARAMETERS, 'd length does not match ' + crv, { field: 'd' });
  const xInt = base64urlBigInt(key.x);
  const yInt = base64urlBigInt(key.y);
  if (xInt === 0n && yInt === 0n) fail(CODE.INVALID_EC_PARAMETERS, 'point at infinity origin is not a valid public key', { field: 'x' });
  return { crv };
}

function validateOkp(key) {
  const crv = expectString(key, 'crv', { maxStringLength: 64 }, true);
  expectBase64url(key, 'x', true);
  expectBase64url(key, 'd', false);
  if (!(crv in OKP_CURVE_BYTES) && crv !== 'X25519' && crv !== 'X448') {
    fail(CODE.INVALID_CURVE, 'unrecognized OKP curve: ' + crv, { field: 'crv' });
  }
  const size = OKP_CURVE_BYTES[crv] === undefined ? (crv === 'X25519' ? 32 : 56) : OKP_CURVE_BYTES[crv];
  if (base64urlBytes(key.x).length !== size) fail(CODE.INVALID_OKP_PARAMETERS, 'x length does not match ' + crv, { field: 'x' });
  if (key.d !== undefined && base64urlBytes(key.d).length !== size) fail(CODE.INVALID_OKP_PARAMETERS, 'd length does not match ' + crv, { field: 'd' });
  if (base64urlBigInt(key.x) === 0n) fail(CODE.INVALID_OKP_PARAMETERS, 'null public key material is not acceptable', { field: 'x' });
  return { crv };
}

function validateOct(key) {
  expectBase64url(key, 'k', true);
  if (base64urlBytes(key.k).length < 16) fail(CODE.INVALID_OCT_PARAMETERS, 'symmetric key material is below the absolute 128-bit floor', { field: 'k' });
  return { keyBytes: base64urlBytes(key.k).length };
}

export function validateJwkStructure(key, bounds) {
  if (!isPlainObject(key)) fail(CODE.INVALID_JWK, 'JWK must be a plain object');
  if (Object.keys(key).length > bounds.maxObjectKeys) fail(CODE.INVALID_JWK, 'JWK exceeds the member-count budget');
  const kty = key.kty;
  if (typeof kty !== 'string') fail(CODE.INVALID_KTY, 'kty must be a string', { field: 'kty' });
  if (!KEY_TYPES.includes(kty)) fail(CODE.INVALID_KTY, 'unrecognized key type: ' + kty, { field: 'kty' });
  for (const member of Object.keys(key)) {
    if (typeof member !== 'string' || member.length === 0) fail(CODE.INVALID_JWK, 'JWK contains an invalid member name');
    if (CONTROL_RE.test(member)) fail(CODE.INVALID_JWK, 'JWK member name contains control characters');
  }
  if (key.alg !== undefined && typeof key.alg !== 'string') fail(CODE.INVALID_ALG, 'alg must be a string', { field: 'alg' });
  if (key.kid !== undefined && typeof key.kid !== 'string') fail(CODE.INVALID_KID, 'kid must be a string', { field: 'kid' });
  validateUseAndKeyOps(key);
  let family;
  if (kty === 'RSA') family = { family: 'RSA', ...validateRsa(key, bounds) };
  else if (kty === 'EC') family = { family: 'EC', ...validateEc(key) };
  else if (kty === 'OKP') family = { family: 'OKP', ...validateOkp(key) };
  else family = { family: 'oct', ...validateOct(key) };
  return family;
}

export function parseJwk(input, options) {
  normalizeOptions(options === undefined ? {} : options, ['bounds'], 'parseJwk');
  const opts = options === undefined ? {} : options;
  const bounds = normalizeBounds(opts);
  const key = materializeJsonInput(input, bounds, bounds.maxDepth, 'parseJwk');
  validateJwkStructure(key, bounds);
  return deepFreeze(key);
}

function finding(code, severity, field, message, extra) {
  const out = { code, severity, field, message };
  if (extra !== undefined) Object.assign(out, extra);
  return out;
}

export function auditJwk(input, options) {
  normalizeOptions(options === undefined ? {} : options, ['bounds', 'allowedCurves', 'context'], 'auditJwk');
  const opts = options === undefined ? {} : options;
  const findings = [];
  let bounds;
  try {
    bounds = normalizeBounds(opts);
  } catch (error) {
    return finalizeReport([finding('INVALID_OPTIONS', 'critical', 'options', error.message)], opts);
  }
  let key;
  try {
    key = materializeJsonInput(input, bounds, bounds.maxDepth, 'auditJwk');
  } catch (error) {
    const code = error instanceof JwkCageError ? error.code.replace('JWKCAGE_', '') : 'INVALID_INPUT';
    return finalizeReport([finding(code, 'critical', 'input', error.message)], opts, bounds);
  }
  let structure;
  try {
    structure = validateJwkStructure(key, bounds);
  } catch (error) {
    const code = error instanceof JwkCageError ? error.code.replace('JWKCAGE_', '') : 'INVALID_JWK';
    findings.push(finding(code, 'critical', error.context && error.context.field ? error.context.field : 'jwk', error.message));
    return finalizeReport(findings, opts, bounds);
  }
  const allowedCurves = opts.allowedCurves === undefined ? DEFAULT_ALLOWED_CURVES : opts.allowedCurves;
  if (!Array.isArray(allowedCurves) || allowedCurves.some((curve) => typeof curve !== 'string')) {
    findings.push(finding('INVALID_OPTIONS', 'critical', 'allowedCurves', 'allowedCurves must be an array of curve names'));
    return finalizeReport(findings, opts, bounds);
  }
  if (structure.family === 'RSA') {
    if (structure.modulusBits < MIN_RSA_MODULUS_BITS) {
      findings.push(finding('RSA_MODULUS_TOO_SMALL', 'critical', 'n', 'RSA modulus is ' + structure.modulusBits + ' bits, below the ' + MIN_RSA_MODULUS_BITS + '-bit floor'));
    }
    if (structure.exponent < BigInt(MIN_RSA_EXPONENT)) {
      findings.push(finding('RSA_EXPONENT_TOO_SMALL', 'critical', 'e', 'RSA public exponent is below 65537'));
    }
    if (structure.exponent % 2n === 0n) findings.push(finding('RSA_EXPONENT_EVEN', 'high', 'e', 'RSA public exponent must be odd'));
    if (structure.modulusBits > 16384) findings.push(finding('RSA_MODULUS_OVERSIZED', 'medium', 'n', 'RSA modulus is impractically large'));
  }
  if (structure.family === 'EC' || structure.family === 'OKP') {
    if (!allowedCurves.includes(structure.crv)) {
      findings.push(finding('CURVE_NOT_ALLOWED', 'critical', 'crv', 'curve ' + structure.crv + ' is not in the policy allowlist'));
    }
  }
  if (structure.family === 'oct') {
    const alg = key.alg;
    const minimum = alg !== undefined && MIN_OCT_BYTES[alg] !== undefined ? MIN_OCT_BYTES[alg] : 16;
    if (structure.keyBytes < minimum) {
      findings.push(finding('OCT_KEY_TOO_SHORT', 'critical', 'k', 'symmetric key of ' + structure.keyBytes + ' bytes is below the floor for ' + (alg === undefined ? 'unrestricted use' : alg)));
    }
    if (structure.keyBytes > 512) findings.push(finding('OCT_KEY_OVERSIZED', 'medium', 'k', 'symmetric key is implausibly large'));
  }
  const privateParams = PRIVATE_KEY_PARAMETERS.filter((param) => key[param] !== undefined);
  if (privateParams.length > 0 && structure.family !== 'oct') {
    findings.push(finding('PRIVATE_MATERIAL_PRESENT', 'high', privateParams[0], 'JWK carries private key parameters: ' + privateParams.join(', ') + '; never publish this key'));
  }
  if (structure.family === 'oct') {
    findings.push(finding('SYMMETRIC_KEY_MATERIAL', 'medium', 'k', 'oct keys are shared secrets and must never appear in a public keyset'));
  }
  if (key.use !== undefined && key.key_ops !== undefined) {
    const signing = new Set(['sign', 'verify']);
    const encryption = new Set(['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
    const ops = key.key_ops;
    const sigOps = ops.filter((op) => signing.has(op)).length;
    const encOps = ops.filter((op) => encryption.has(op)).length;
    if (key.use === 'sig' && encOps > 0) findings.push(finding('USE_KEY_OPS_MISMATCH', 'high', 'key_ops', 'use sig conflicts with encryption key_ops entries'));
    if (key.use === 'enc' && sigOps > 0) findings.push(finding('USE_KEY_OPS_MISMATCH', 'high', 'key_ops', 'use enc conflicts with signing key_ops entries'));
  }
  if (key.alg !== undefined) {
    if (key.alg.toLowerCase() === 'none') findings.push(finding('ALG_NONE', 'critical', 'alg', 'the none algorithm is forbidden'));
    else if (DEPRECATED_ALGORITHMS.includes(key.alg)) findings.push(finding('ALG_DEPRECATED', 'high', 'alg', key.alg + ' is deprecated or uses broken cryptography'));
    else {
      const familyMismatch = algFamilyMismatch(key.alg, structure.family);
      if (familyMismatch) findings.push(finding('ALG_KTY_MISMATCH', 'critical', 'alg', key.alg + ' cannot be used with key type ' + structure.family));
    }
  }
  if (key.kid !== undefined) {
    for (const hit of auditKidString(key.kid, bounds.maxKidLength)) findings.push(hit);
  }
  if (key.x5u !== undefined) {
    for (const hit of auditEndpointUrl(key.x5u, 'x5u')) findings.push(hit);
  }
  if (key.x5c !== undefined) {
    if (!Array.isArray(key.x5c)) findings.push(finding('X5C_TYPE', 'high', 'x5c', 'x5c must be an array of certificate strings'));
    else {
      if (key.x5c.length === 0) findings.push(finding('X5C_EMPTY', 'medium', 'x5c', 'x5c certificate chain is empty'));
      if (key.x5c.length > 8) findings.push(finding('X5C_TOO_DEEP', 'medium', 'x5c', 'x5c chain exceeds the depth budget'));
      for (const cert of key.x5c) {
        if (typeof cert !== 'string') {
          findings.push(finding('X5C_ENTRY_TYPE', 'high', 'x5c', 'x5c entries must be strings'));
          break;
        }
      }
    }
  }
  if (key.x5t !== undefined && (typeof key.x5t !== 'string' || !isBase64url(key.x5t))) {
    findings.push(finding('X5T_ENCODING', 'medium', 'x5t', 'x5t thumbprint is not valid base64url'));
  }
  return finalizeReport(findings, opts, bounds);
}

function algFamilyMismatch(alg, family) {
  if (/^HS(256|384|512)$/u.test(alg)) return family !== 'oct';
  if (/^(RS|PS)(256|384|512)$/u.test(alg) || alg === 'RSA1_5' || /^RSA-OAEP/u.test(alg)) return family !== 'RSA';
  if (/^ES(256|384|512)$/u.test(alg) || /^ECDH-ES/u.test(alg)) return family !== 'EC';
  if (alg === 'EdDSA') return family !== 'OKP';
  if (/^A(128|192|256)(KW|GCMKW)$/u.test(alg) || alg === 'dir') return family !== 'oct';
  return false;
}

function finalizeReport(findings, opts, bounds) {
  const cap = bounds === undefined ? DEFAULT_BOUNDS.maxFindings : bounds.maxFindings;
  const truncated = findings.length > cap;
  const limited = truncated ? findings.slice(0, cap) : findings;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const hit of limited) {
    if (counts[hit.severity] !== undefined) counts[hit.severity] += 1;
  }
  const safe = counts.critical === 0 && counts.high === 0;
  return deepFreeze({
    safe,
    findings: limited.map((hit) => Object.freeze({ ...hit })),
    counts,
    truncated,
    keysAudited: limited.length === 0 ? 0 : 1,
    context: opts.context === undefined ? 'jwk' : String(opts.context)
  });
}

export function stripPrivateMaterial(input) {
  const key = materializeJsonInput(input, DEFAULT_BOUNDS, DEFAULT_BOUNDS.maxDepth, 'stripPrivateMaterial');
  for (const param of PRIVATE_KEY_PARAMETERS) delete key[param];
  return deepFreeze(key);
}

export function computeJwkThumbprint(input, hashAlgorithm) {
  const algorithm = hashAlgorithm === undefined ? 'sha256' : hashAlgorithm;
  if (!['sha256', 'sha384', 'sha512'].includes(algorithm)) {
    fail(CODE.INVALID_THUMBPRINT_INPUT, 'thumbprint hash must be sha256, sha384, or sha512');
  }
  const key = materializeJsonInput(input, DEFAULT_BOUNDS, DEFAULT_BOUNDS.maxDepth, 'computeJwkThumbprint');
  const kty = key.kty;
  let canonical;
  if (kty === 'RSA') {
    for (const member of ['e', 'n']) expectBase64url(key, member, true);
    canonical = { e: key.e, kty: 'RSA', n: key.n };
  } else if (kty === 'EC') {
    for (const member of ['crv', 'x', 'y']) {
      if (typeof key[member] !== 'string') fail(CODE.INVALID_THUMBPRINT_INPUT, 'EC thumbprint requires string ' + member);
    }
    canonical = { crv: key.crv, kty: 'EC', x: key.x, y: key.y };
  } else if (kty === 'OKP') {
    for (const member of ['crv', 'x']) {
      if (typeof key[member] !== 'string') fail(CODE.INVALID_THUMBPRINT_INPUT, 'OKP thumbprint requires string ' + member);
    }
    canonical = { crv: key.crv, kty: 'OKP', x: key.x };
  } else if (kty === 'oct') {
    if (typeof key.k !== 'string') fail(CODE.INVALID_THUMBPRINT_INPUT, 'oct thumbprint requires string k');
    canonical = { k: key.k, kty: 'oct' };
  } else {
    fail(CODE.INVALID_THUMBPRINT_INPUT, 'unsupported kty for thumbprint');
  }
  const json = JSON.stringify(canonical);
  const digest = createHash(algorithm).update(json, 'utf8').digest();
  return digest.toString('base64url');
}
