export const JWKCAGE_VERSION: '1.0.0';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  readonly code: string;
  readonly severity: Severity;
  readonly field: string;
  readonly message: string;
  readonly keyIndex?: number;
}

export interface AuditCounts {
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly info: number;
}

export interface AuditReport {
  readonly safe: boolean;
  readonly findings: readonly Finding[];
  readonly counts: AuditCounts;
  readonly truncated: boolean;
  readonly keysAudited: number;
  readonly context: string;
}

export interface Bounds {
  readonly maxJsonBytes?: number;
  readonly maxKeys?: number;
  readonly maxObjectKeys?: number;
  readonly maxDepth?: number;
  readonly maxStringLength?: number;
  readonly maxFindings?: number;
  readonly maxKidLength?: number;
}

export interface ParseJwkOptions {
  readonly bounds?: Bounds;
}

export interface AuditJwkOptions {
  readonly bounds?: Bounds;
  readonly allowedCurves?: readonly string[];
  readonly context?: string;
}

export interface AuditJwksOptions {
  readonly bounds?: Bounds;
  readonly allowedCurves?: readonly string[];
  readonly requireKid?: boolean;
}

export interface AuditJwtHeaderOptions {
  readonly bounds?: Bounds;
  readonly algorithms?: readonly string[];
  readonly expectedKty?: 'RSA' | 'EC' | 'OKP' | 'oct';
  readonly requireKid?: boolean;
  readonly kind?: 'jws' | 'jwe';
}

export interface SelectVerificationKeyOptions {
  readonly algorithms: readonly string[];
  readonly allowSymmetric?: boolean;
  readonly bounds?: Bounds;
  readonly allowedCurves?: readonly string[];
}

export type JsonValue = string | number | boolean | null | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export interface JwkObject {
  readonly kty: string;
  readonly use?: string;
  readonly key_ops?: readonly string[];
  readonly alg?: string;
  readonly kid?: string;
  readonly x5u?: string;
  readonly x5c?: readonly string[];
  readonly x5t?: string;
  readonly crv?: string;
  readonly x?: string;
  readonly y?: string;
  readonly n?: string;
  readonly e?: string;
  readonly k?: string;
  readonly [member: string]: JsonValue | undefined;
}

export declare class JwkCageError extends Error {
  readonly code: string;
  readonly detail: string;
  readonly context?: unknown;
}

export declare function isJwkCageError(value: unknown): value is JwkCageError;
export declare function parseJwk(input: unknown, options?: ParseJwkOptions): JwkObject;
export declare function auditJwk(input: unknown, options?: AuditJwkOptions): AuditReport;
export declare function auditJwks(input: unknown, options?: AuditJwksOptions): AuditReport;
export declare function auditJwtHeader(input: unknown, options?: AuditJwtHeaderOptions): AuditReport;
export declare function selectVerificationKey(jwks: unknown, header: unknown, options: SelectVerificationKeyOptions): JwkObject;
export declare function stripPrivateMaterial(input: unknown): JwkObject;
export declare function computeJwkThumbprint(input: unknown, hashAlgorithm?: 'sha256' | 'sha384' | 'sha512'): string;
export declare function auditKidString(kid: unknown, maxKidLength?: number): readonly Finding[];
export declare function auditEndpointUrl(value: unknown, field: string): readonly Finding[];

export declare const JWKCAGE_ERROR_CODES: Readonly<Record<string, string>>;
export declare const JWKCAGE_SEVERITY: Readonly<Record<string, Severity>>;
export declare const PRIVATE_KEY_PARAMETERS: readonly string[];
export declare const ASYMMETRIC_PRIVATE_PARAMETERS: readonly string[];
export declare const PROTOTYPE_POLLUTION_KEYS: readonly string[];
export declare const KEY_TYPES: readonly string[];
export declare const USE_VALUES: readonly string[];
export declare const KEY_OPS_VALUES: readonly string[];
export declare const DEFAULT_ALLOWED_CURVES: readonly string[];
export declare const EC_CURVE_BYTES: Readonly<Record<string, number>>;
export declare const OKP_CURVE_BYTES: Readonly<Record<string, number>>;
export declare const HMAC_ALGORITHMS: readonly string[];
export declare const RSA_ALGORITHMS: readonly string[];
export declare const EC_ALGORITHMS: readonly string[];
export declare const OKP_ALGORITHMS: readonly string[];
export declare const OCT_ALGORITHMS: readonly string[];
export declare const DEPRECATED_ALGORITHMS: readonly string[];
export declare const SIGNING_ALGORITHMS: readonly string[];
export declare const JWE_CONTENT_ENCRYPTION: readonly string[];
export declare const CURVE_FOR_ES: Readonly<Record<string, string>>;
export declare const MIN_RSA_MODULUS_BITS: number;
export declare const MIN_RSA_EXPONENT: number;
export declare const MIN_OCT_BYTES: Readonly<Record<string, number>>;
export declare const DEFAULT_BOUNDS: Readonly<Record<string, number>>;
export declare const HARD_BOUNDS: Readonly<Record<string, number>>;

declare const JwkCage: {
  readonly parseJwk: typeof parseJwk;
  readonly auditJwk: typeof auditJwk;
  readonly auditJwks: typeof auditJwks;
  readonly auditJwtHeader: typeof auditJwtHeader;
  readonly selectVerificationKey: typeof selectVerificationKey;
  readonly stripPrivateMaterial: typeof stripPrivateMaterial;
  readonly computeJwkThumbprint: typeof computeJwkThumbprint;
};

export default JwkCage;
