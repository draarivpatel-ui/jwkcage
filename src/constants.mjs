export const JWKCAGE_VERSION = '1.0.0';

export const JWKCAGE_ERROR_CODES = Object.freeze({
  INVALID_INPUT: 'JWKCAGE_INVALID_INPUT',
  INVALID_OPTIONS: 'JWKCAGE_INVALID_OPTIONS',
  INPUT_TOO_LARGE: 'JWKCAGE_INPUT_TOO_LARGE',
  MALFORMED_JSON: 'JWKCAGE_MALFORMED_JSON',
  DUPLICATE_JSON_KEY: 'JWKCAGE_DUPLICATE_JSON_KEY',
  PROTOTYPE_POLLUTION: 'JWKCAGE_PROTOTYPE_POLLUTION',
  INVALID_JWK: 'JWKCAGE_INVALID_JWK',
  INVALID_JWKS: 'JWKCAGE_INVALID_JWKS',
  INVALID_KTY: 'JWKCAGE_INVALID_KTY',
  INVALID_BASE64URL: 'JWKCAGE_INVALID_BASE64URL',
  INVALID_ALG: 'JWKCAGE_INVALID_ALG',
  INVALID_KID: 'JWKCAGE_INVALID_KID',
  INVALID_USE: 'JWKCAGE_INVALID_USE',
  INVALID_KEY_OPS: 'JWKCAGE_INVALID_KEY_OPS',
  INVALID_CURVE: 'JWKCAGE_INVALID_CURVE',
  INVALID_RSA_PARAMETERS: 'JWKCAGE_INVALID_RSA_PARAMETERS',
  INVALID_EC_PARAMETERS: 'JWKCAGE_INVALID_EC_PARAMETERS',
  INVALID_OKP_PARAMETERS: 'JWKCAGE_INVALID_OKP_PARAMETERS',
  INVALID_OCT_PARAMETERS: 'JWKCAGE_INVALID_OCT_PARAMETERS',
  PRIVATE_MATERIAL: 'JWKCAGE_PRIVATE_MATERIAL',
  UNSAFE_URL: 'JWKCAGE_UNSAFE_URL',
  ALG_NONE_FORBIDDEN: 'JWKCAGE_ALG_NONE_FORBIDDEN',
  ALGORITHM_CONFUSION: 'JWKCAGE_ALGORITHM_CONFUSION',
  INLINE_KEY_INJECTION: 'JWKCAGE_INLINE_KEY_INJECTION',
  ALGORITHMS_REQUIRED: 'JWKCAGE_ALGORITHMS_REQUIRED',
  KEY_NOT_FOUND: 'JWKCAGE_KEY_NOT_FOUND',
  AMBIGUOUS_KEY: 'JWKCAGE_AMBIGUOUS_KEY',
  UNSAFE_KEY_SET: 'JWKCAGE_UNSAFE_KEY_SET',
  UNSAFE_HEADER: 'JWKCAGE_UNSAFE_HEADER',
  KEY_USE_MISMATCH: 'JWKCAGE_KEY_USE_MISMATCH',
  INVALID_THUMBPRINT_INPUT: 'JWKCAGE_INVALID_THUMBPRINT_INPUT'
});

export const JWKCAGE_SEVERITY = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
});

export const PRIVATE_KEY_PARAMETERS = Object.freeze(['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth']);
export const ASYMMETRIC_PRIVATE_PARAMETERS = Object.freeze(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']);
export const PROTOTYPE_POLLUTION_KEYS = Object.freeze(['__proto__', 'constructor', 'prototype']);
export const KEY_TYPES = Object.freeze(['RSA', 'EC', 'OKP', 'oct']);
export const USE_VALUES = Object.freeze(['sig', 'enc']);
export const KEY_OPS_VALUES = Object.freeze(['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits']);
export const DEFAULT_ALLOWED_CURVES = Object.freeze(['P-256', 'P-384', 'P-521', 'Ed25519', 'Ed448']);
export const EC_CURVE_BYTES = Object.freeze({ 'P-256': 32, 'P-384': 48, 'P-521': 66 });
export const OKP_CURVE_BYTES = Object.freeze({ Ed25519: 32, Ed448: 57 });
export const HMAC_ALGORITHMS = Object.freeze(['HS256', 'HS384', 'HS512']);
export const RSA_ALGORITHMS = Object.freeze(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512']);
export const EC_ALGORITHMS = Object.freeze(['ES256', 'ES384', 'ES512', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']);
export const OKP_ALGORITHMS = Object.freeze(['EdDSA']);
export const OCT_ALGORITHMS = Object.freeze(['HS256', 'HS384', 'HS512', 'dir', 'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW']);
export const DEPRECATED_ALGORITHMS = Object.freeze(['RSA1_5', 'RS1', 'HS1']);
export const SIGNING_ALGORITHMS = Object.freeze(['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']);
export const JWE_CONTENT_ENCRYPTION = Object.freeze(['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512', 'A128GCM', 'A192GCM', 'A256GCM']);
export const CURVE_FOR_ES = Object.freeze({ ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' });
export const MIN_RSA_MODULUS_BITS = 2048;
export const MIN_RSA_EXPONENT = 65537;
export const MIN_OCT_BYTES = Object.freeze({ HS256: 32, HS384: 48, HS512: 64, dir: 32 });
export const DEFAULT_BOUNDS = Object.freeze({
  maxJsonBytes: 16384,
  maxKeys: 128,
  maxObjectKeys: 128,
  maxDepth: 24,
  maxStringLength: 4096,
  maxFindings: 256,
  maxKidLength: 128
});
export const HARD_BOUNDS = Object.freeze({
  maxJsonBytes: 262144,
  maxKeys: 512,
  maxObjectKeys: 512,
  maxDepth: 64,
  maxStringLength: 16384,
  maxFindings: 1024,
  maxKidLength: 512
});
