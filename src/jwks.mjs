/* JWKS auditing and fail-closed verification-key selection. */
import {
  CURVE_FOR_ES,
  DEFAULT_BOUNDS,
  HMAC_ALGORITHMS,
  JWKCAGE_ERROR_CODES as CODE,
  KEY_TYPES,
  PRIVATE_KEY_PARAMETERS,
  SIGNING_ALGORITHMS
} from './constants.mjs';
import { fail } from './errors.mjs';
import {
  auditJwk,
  computeJwkThumbprint,
  deepFreeze,
  isPlainObject,
  materializeJsonInput,
  normalizeBounds,
  normalizeOptions,
  stripPrivateMaterial,
  validateJwkStructure
} from './keys.mjs';
import { capFindings } from './reporting.mjs';

function finding(code, severity, field, message, extra) {
  const out = { code, severity, field, message };
  if (extra !== undefined) Object.assign(out, extra);
  return out;
}

function finalizeReport(allFindings, keyCount, cap) {
  const capped = capFindings(allFindings, cap);
  const counts = capped.counts;
  const safe = counts.critical === 0 && counts.high === 0;
  return deepFreeze({
    safe,
    findings: capped.limited.map((hit) => Object.freeze({ ...hit })),
    counts,
    truncated: capped.truncated,
    keysAudited: keyCount,
    context: 'jwks'
  });
}

export function auditJwks(input, options) {
  normalizeOptions(options === undefined ? {} : options, ['bounds', 'allowedCurves', 'requireKid', 'allowSymmetricKeys'], 'auditJwks');
  const opts = options === undefined ? {} : options;
  let bounds;
  try {
    bounds = normalizeBounds(opts);
  } catch (error) {
    return finalizeReport([finding('INVALID_OPTIONS', 'critical', 'options', error.message)], 0, DEFAULT_BOUNDS.maxFindings);
  }
  const cap = bounds.maxFindings;
  const findings = [];
  const push = (hit) => {
    findings.push(hit);
  };
  let set;
  try {
    set = materializeJsonInput(input, bounds, bounds.maxDepth, 'auditJwks');
  } catch (error) {
    push(finding(error.code === undefined ? 'INVALID_INPUT' : error.code.replace('JWKCAGE_', ''), 'critical', 'input', error.message));
    return finalizeReport(findings, 0, cap);
  }
  if (!Array.isArray(set.keys)) {
    push(finding('INVALID_JWKS', 'critical', 'keys', 'JWKS must carry a keys array'));
    return finalizeReport(findings, 0, cap);
  }
  if (set.keys.length > bounds.maxKeys) {
    push(finding('JWKS_TOO_MANY_KEYS', 'critical', 'keys', 'JWKS exceeds the key-count budget'));
    return finalizeReport(findings, set.keys.length, cap);
  }
  const keyCount = set.keys.length;
  if (keyCount === 0) push(finding('JWKS_EMPTY', 'medium', 'keys', 'JWKS contains no keys'));
  const seenKids = new Map();
  const seenThumbprints = new Map();
  let index = 0;
  for (const entry of set.keys) {
    const prefix = 'keys[' + index + ']';
    const keyOptions = { context: 'jwks-key' };
    if (opts.bounds !== undefined) keyOptions.bounds = opts.bounds;
    if (opts.allowedCurves !== undefined) keyOptions.allowedCurves = opts.allowedCurves;
    const report = auditJwk(entry, keyOptions);
    for (const hit of report.findings) {
      push({ ...hit, field: hit.field === 'input' || hit.field === 'jwk' ? prefix : prefix + '.' + hit.field, keyIndex: index });
    }
    if (!isPlainObject(entry)) {
      index += 1;
      continue;
    }
    const symmetricPermitted = opts.allowSymmetricKeys === true && entry.kty === 'oct';
    for (const param of PRIVATE_KEY_PARAMETERS) {
      if (entry[param] !== undefined) {
        if (symmetricPermitted && param === 'k') continue;
        push(finding('PUBLIC_JWKS_PRIVATE_LEAK', 'critical', prefix + '.' + param, 'private or secret parameter ' + param + ' is exposed in a public JWKS', { keyIndex: index }));
      }
    }
    if (entry.kty === 'oct' && !symmetricPermitted) {
      push(finding('PUBLIC_JWKS_SYMMETRIC_KEY', 'critical', prefix + '.kty', 'an oct symmetric secret key must never be published in a JWKS', { keyIndex: index }));
    }
    const kid = entry.kid;
    if (kid === undefined || kid === '') {
      if (keyCount > 1) push(finding('KID_MISSING', 'high', prefix + '.kid', 'key in a multi-key set has no kid; key selection becomes ambiguous', { keyIndex: index }));
    } else if (typeof kid === 'string') {
      if (seenKids.has(kid)) {
        push(finding('KID_DUPLICATE_COLLISION', 'critical', prefix + '.kid', 'duplicate kid collides with keys[' + seenKids.get(kid) + ']; attackers can force wrong-key selection', { keyIndex: index }));
      } else {
        seenKids.set(kid, index);
      }
    }
    try {
      validateJwkStructure(entry, bounds);
      const thumbprint = computeJwkThumbprint(entry);
      if (seenThumbprints.has(thumbprint)) {
        push(finding('KEY_MATERIAL_DUPLICATE', 'high', prefix, 'key material duplicates keys[' + seenThumbprints.get(thumbprint) + '] under a different identity', { keyIndex: index }));
      } else {
        seenThumbprints.set(thumbprint, index);
      }
    } catch {
      // structural findings already reported per key
    }
    index += 1;
  }
  const required = opts.requireKid === undefined ? false : opts.requireKid;
  if (required === true) {
    let missing = 0;
    for (const entry of set.keys) {
      if (isPlainObject(entry) && (entry.kid === undefined || entry.kid === '')) missing += 1;
    }
    if (missing > 0) push(finding('KID_REQUIRED', 'critical', 'keys', missing + ' key(s) lack the policy-required kid'));
  }
  return finalizeReport(findings, keyCount, cap);
}

function algorithmCompatibleWithKey(alg, key) {
  if (typeof alg !== 'string' || typeof key.kty !== 'string') return false;
  if (HMAC_ALGORITHMS.includes(alg)) return key.kty === 'oct';
  if (/^(RS|PS)(256|384|512)$/u.test(alg)) return key.kty === 'RSA';
  if (/^ES(256|384|512)$/u.test(alg)) {
    if (key.kty !== 'EC') return false;
    return key.crv === CURVE_FOR_ES[alg];
  }
  if (alg === 'EdDSA') {
    return key.kty === 'OKP' && (key.crv === 'Ed25519' || key.crv === 'Ed448');
  }
  return false;
}

function keyUseCompatible(key) {
  if (key.use !== undefined && key.use !== 'sig') return false;
  if (key.key_ops !== undefined && !key.key_ops.includes('verify')) return false;
  return true;
}

export function selectVerificationKey(jwksInput, headerInput, options) {
  normalizeOptions(options === undefined ? {} : options, ['algorithms', 'allowSymmetric', 'bounds', 'allowedCurves'], 'selectVerificationKey');
  const opts = options === undefined ? {} : options;
  const algorithms = opts.algorithms;
  if (!Array.isArray(algorithms) || algorithms.length === 0 || algorithms.some((alg) => typeof alg !== 'string' || alg.length === 0)) {
    fail(CODE.ALGORITHMS_REQUIRED, 'selectVerificationKey requires a non-empty explicit algorithms allowlist');
  }
  for (const alg of algorithms) {
    if (alg.toLowerCase() === 'none') fail(CODE.ALG_NONE_FORBIDDEN, 'the none algorithm must never be allowlisted');
    if (!SIGNING_ALGORITHMS.includes(alg)) fail(CODE.INVALID_ALG, 'allowlist entry is not a recognized JWS signing algorithm: ' + alg);
  }
  if (HMAC_ALGORITHMS.some((alg) => algorithms.includes(alg)) && opts.allowSymmetric !== true) {
    fail(CODE.ALGORITHM_CONFUSION, 'HMAC verification requires explicit allowSymmetric: true so symmetric keys are never confused for public keys');
  }
  const bounds = normalizeBounds(opts);
  const auditOptions = {};
  if (opts.bounds !== undefined) auditOptions.bounds = opts.bounds;
  if (opts.allowedCurves !== undefined) auditOptions.allowedCurves = opts.allowedCurves;
  if (opts.allowSymmetric === true) auditOptions.allowSymmetricKeys = true;
  const jwksReport = auditJwks(jwksInput, auditOptions);
  if (!jwksReport.safe) {
    fail(CODE.UNSAFE_KEY_SET, 'JWKS failed the security audit and cannot be used for verification', {
      findings: jwksReport.findings.slice(0, 8).map((hit) => hit.code)
    });
  }
  const set = materializeJsonInput(jwksInput, bounds, bounds.maxDepth, 'selectVerificationKey');
  let header;
  if (typeof headerInput === 'string' && !headerInput.trim().startsWith('{')) {
    fail(CODE.INVALID_INPUT, 'selectVerificationKey takes a decoded header object or JSON string, not a compact token segment; decode with auditJwtHeader first');
  }
  header = materializeJsonInput(headerInput, bounds, bounds.maxDepth, 'selectVerificationKey');
  const alg = header.alg;
  if (typeof alg !== 'string' || alg.length === 0) fail(CODE.INVALID_ALG, 'header alg is missing');
  if (alg.toLowerCase() === 'none') fail(CODE.ALG_NONE_FORBIDDEN, 'the none algorithm is forbidden');
  if (!algorithms.includes(alg)) fail(CODE.INVALID_ALG, 'header alg is outside the explicit allowlist: ' + alg);
  if (header.jwk !== undefined || header.x5c !== undefined) {
    fail(CODE.INLINE_KEY_INJECTION, 'header embeds inline key material; keys must come from the trusted keyset only');
  }
  const kid = header.kid;
  const candidates = [];
  let index = 0;
  for (const entry of set.keys) {
    if (!isPlainObject(entry)) {
      index += 1;
      continue;
    }
    if (!KEY_TYPES.includes(entry.kty)) {
      index += 1;
      continue;
    }
    if (!algorithmCompatibleWithKey(alg, entry)) {
      index += 1;
      continue;
    }
    if (!keyUseCompatible(entry)) {
      index += 1;
      continue;
    }
    if (entry.alg !== undefined && entry.alg !== alg) {
      index += 1;
      continue;
    }
    if (kid !== undefined) {
      if (typeof kid !== 'string') fail(CODE.INVALID_KID, 'header kid must be a string');
      if (entry.kid !== kid) {
        index += 1;
        continue;
      }
    }
    candidates.push({ entry, index });
    index += 1;
  }
  if (candidates.length === 0) {
    fail(CODE.KEY_NOT_FOUND, kid === undefined ? 'no key in the trusted set can verify ' + alg : 'no key with the requested kid can verify ' + alg);
  }
  if (candidates.length > 1) {
    fail(CODE.AMBIGUOUS_KEY, 'multiple keys match the selection criteria; refusing ambiguous key selection');
  }
  const match = candidates[0].entry;
  if (match.kty === 'oct') {
    if (!HMAC_ALGORITHMS.includes(alg) || opts.allowSymmetric !== true) {
      fail(CODE.ALGORITHM_CONFUSION, 'symmetric key use requires explicit allowSymmetric: true');
    }
    return deepFreeze(JSON.parse(JSON.stringify(match)));
  }
  return stripPrivateMaterial(match);
}
