/* JWS/JWE header security auditing: algorithm confusion, inline key injection, SSRF endpoints, kid injection. */
import {
  DEPRECATED_ALGORITHMS,
  HMAC_ALGORITHMS,
  JWKCAGE_ERROR_CODES as CODE,
  JWE_CONTENT_ENCRYPTION,
  SIGNING_ALGORITHMS
} from './constants.mjs';
import { JwkCageError } from './errors.mjs';
import {
  auditKidString,
  deepFreeze,
  isBase64url,
  materializeJsonInput,
  normalizeBounds,
  normalizeOptions
} from './keys.mjs';
import { auditEndpointUrl } from './urlsec.mjs';

const REGISTERED_HEADER_PARAMETERS = new Set([
  'alg', 'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'typ', 'cty', 'crit',
  'enc', 'zip', 'epk', 'apu', 'apv', 'iv', 'tag', 'p2s', 'p2c', 'b64'
]);

const ALL_KNOWN_ALGORITHMS = new Set([
  ...SIGNING_ALGORITHMS,
  ...DEPRECATED_ALGORITHMS,
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  'dir', 'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW'
]);

function finding(code, severity, field, message) {
  return { code, severity, field, message };
}

function finalizeReport(findings, cap) {
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
    keysAudited: 0,
    context: 'jwt-header'
  });
}

export function auditJwtHeader(input, options) {
  normalizeOptions(options === undefined ? {} : options, ['algorithms', 'expectedKty', 'bounds', 'requireKid', 'kind'], 'auditJwtHeader');
  const opts = options === undefined ? {} : options;
  let bounds;
  try {
    bounds = normalizeBounds(opts);
  } catch (error) {
    return finalizeReport([finding('INVALID_OPTIONS', 'critical', 'options', error.message)], 256);
  }
  const cap = bounds.maxFindings;
  let header;
  try {
    header = materializeJsonInput(input, bounds, bounds.maxDepth, 'auditJwtHeader');
  } catch (error) {
    const code = error instanceof JwkCageError ? error.code.replace('JWKCAGE_', '') : 'INVALID_INPUT';
    return finalizeReport([finding(code, 'critical', 'input', error.message)], cap);
  }
  const findings = [];
  const push = (hit) => {
    if (findings.length < cap) findings.push(hit);
  };
  if (Object.keys(header).length > bounds.maxObjectKeys) {
    push(finding('HEADER_TOO_MANY_MEMBERS', 'high', 'header', 'header exceeds the member-count budget'));
  }
  const alg = header.alg;
  if (alg === undefined) {
    push(finding('ALG_MISSING', 'critical', 'alg', 'header has no alg; unsigned or algorithm-less tokens must be rejected'));
  } else if (typeof alg !== 'string' || alg.length === 0) {
    push(finding('ALG_TYPE', 'critical', 'alg', 'alg must be a non-empty string'));
  } else {
    if (alg.toLowerCase() === 'none') {
      push(finding('ALG_NONE', 'critical', 'alg', 'the none algorithm disables signature verification entirely'));
    } else if (!ALL_KNOWN_ALGORITHMS.has(alg)) {
      push(finding('ALG_UNRECOGNIZED', 'high', 'alg', 'unrecognized algorithm: ' + alg));
    } else {
      if (DEPRECATED_ALGORITHMS.includes(alg)) {
        push(finding('ALG_DEPRECATED', 'high', 'alg', alg + ' is deprecated or cryptographically broken'));
      }
      if (alg === 'HS256' || alg === 'HS384' || alg === 'HS512') {
        if (opts.expectedKty !== undefined && opts.expectedKty !== 'oct') {
          push(finding('ALGORITHM_CONFUSION', 'critical', 'alg', alg + ' with an asymmetric ' + opts.expectedKty + ' key is the classic symmetric-asymmetric confusion attack'));
        }
      }
      if (opts.expectedKty !== undefined) {
        const expected = opts.expectedKty;
        const mismatch =
          (expected === 'RSA' && !/^(RS|PS)(256|384|512)$/u.test(alg) && !/^RSA-OAEP/u.test(alg) && alg !== 'RSA1_5') ||
          (expected === 'EC' && !/^ES(256|384|512)$/u.test(alg) && !/^ECDH-ES/u.test(alg)) ||
          (expected === 'OKP' && alg !== 'EdDSA') ||
          (expected === 'oct' && !HMAC_ALGORITHMS.includes(alg) && !/^A(128|192|256)(KW|GCMKW)$/u.test(alg) && alg !== 'dir');
        if (mismatch) push(finding('ALG_KTY_MISMATCH', 'critical', 'alg', alg + ' cannot be satisfied by key type ' + expected));
      }
      if (opts.algorithms !== undefined) {
        if (!Array.isArray(opts.algorithms) || opts.algorithms.some((entry) => typeof entry !== 'string')) {
          push(finding('INVALID_OPTIONS', 'critical', 'algorithms', 'algorithms must be an array of strings'));
        } else if (!opts.algorithms.includes(alg)) {
          push(finding('ALG_NOT_ALLOWLISTED', 'high', 'alg', alg + ' is outside the caller algorithm allowlist'));
        }
      }
    }
  }
  if (header.jwk !== undefined) {
    push(finding('INLINE_JWK_INJECTION', 'critical', 'jwk', 'header embeds an inline jwk; trusting it lets attackers self-sign tokens'));
  }
  if (header.x5c !== undefined) {
    push(finding('INLINE_X5C_INJECTION', 'critical', 'x5c', 'header embeds an inline x5c certificate chain; trusting it lets attackers self-sign tokens'));
  }
  if (header.jku !== undefined) {
    for (const hit of auditEndpointUrl(header.jku, 'jku')) push(hit);
  }
  if (header.x5u !== undefined) {
    for (const hit of auditEndpointUrl(header.x5u, 'x5u')) push(hit);
  }
  if (header.kid !== undefined) {
    for (const hit of auditKidString(header.kid, bounds.maxKidLength)) push(hit);
  } else if (opts.requireKid === true) {
    push(finding('KID_REQUIRED', 'high', 'kid', 'policy requires a kid for key rotation'));
  }
  if (header.crit !== undefined) {
    if (!Array.isArray(header.crit)) {
      push(finding('CRIT_TYPE', 'high', 'crit', 'crit must be an array of extension parameter names'));
    } else {
      const names = new Set();
      for (const entry of header.crit) {
        if (typeof entry !== 'string' || entry.length === 0) {
          push(finding('CRIT_ENTRY_TYPE', 'high', 'crit', 'crit entries must be non-empty strings'));
          break;
        }
        if (names.has(entry)) {
          push(finding('CRIT_DUPLICATE', 'medium', 'crit', 'crit contains a duplicate entry'));
          break;
        }
        names.add(entry);
      }
      for (const entry of names) {
        if (REGISTERED_HEADER_PARAMETERS.has(entry)) {
          push(finding('CRIT_REGISTERED_PARAMETER', 'high', 'crit', 'crit must not list the registered parameter ' + entry));
        }
        if (header[entry] === undefined) {
          push(finding('CRIT_EXTENSION_MISSING', 'critical', 'crit', 'critical extension ' + entry + ' is absent; the header must be rejected unless it is understood'));
        } else {
          push(finding('CRIT_UNVERIFIED_EXTENSION', 'high', 'crit', 'critical extension ' + entry + ' is present but this library cannot verify its semantics'));
        }
      }
    }
  }
  if (header.typ !== undefined && typeof header.typ !== 'string') push(finding('TYP_TYPE', 'medium', 'typ', 'typ must be a string'));
  if (header.cty !== undefined && typeof header.cty !== 'string') push(finding('CTY_TYPE', 'medium', 'cty', 'cty must be a string'));
  const kind = opts.kind;
  if (kind !== undefined && !['jws', 'jwe'].includes(kind)) push(finding('INVALID_OPTIONS', 'critical', 'kind', 'kind must be jws or jwe when provided'));
  if (kind === 'jwe' || (kind === undefined && header.enc !== undefined)) {
    if (header.enc === undefined) {
      if (kind === 'jwe') push(finding('ENC_MISSING', 'high', 'enc', 'JWE headers must declare a content encryption algorithm'));
    } else if (!JWE_CONTENT_ENCRYPTION.includes(header.enc)) {
      push(finding('ENC_UNRECOGNIZED', 'high', 'enc', 'unrecognized or weak content encryption algorithm'));
    }
    if (header.zip !== undefined && header.zip !== 'DEF') push(finding('ZIP_UNRECOGNIZED', 'medium', 'zip', 'unrecognized compression algorithm'));
    if (header.zip === 'DEF') push(finding('ZIP_COMPRESSION_ENABLED', 'medium', 'zip', 'compression before encryption can enable oracle attacks'));
  }
  if (header.epk !== undefined) {
    push(finding('EPK_UNTRUSTED', 'high', 'epk', 'ephemeral key in header must be validated against curve policy before use'));
  }
  if (header.iv !== undefined && !isBase64url(header.iv)) push(finding('IV_ENCODING', 'medium', 'iv', 'iv is not valid base64url'));
  if (header.tag !== undefined && !isBase64url(header.tag)) push(finding('TAG_ENCODING', 'medium', 'tag', 'tag is not valid base64url'));
  if (header.p2c !== undefined) {
    if (!Number.isSafeInteger(header.p2c) || header.p2c < 1) {
      push(finding('P2C_INVALID', 'high', 'p2c', 'p2c must be a positive integer'));
    } else if (header.p2c < 100000) {
      push(finding('P2C_TOO_LOW', 'high', 'p2c', 'PBES2 iteration count is below the 100000 floor'));
    } else if (header.p2c > 10000000) {
      push(finding('P2C_EXCESSIVE', 'medium', 'p2c', 'PBES2 iteration count is a denial-of-service amplifier'));
    }
  }
  if (header.p2s !== undefined && !isBase64url(header.p2s)) push(finding('P2S_ENCODING', 'medium', 'p2s', 'p2s is not valid base64url'));
  return finalizeReport(findings, cap);
}
