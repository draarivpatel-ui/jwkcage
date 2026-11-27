export class JwkCageError extends Error {
  constructor(code, detail = '', context = undefined) {
    super(detail === '' ? code : code + ': ' + detail);
    this.name = 'JwkCageError';
    this.code = code;
    this.detail = detail;
    if (context !== undefined) this.context = context;
  }
}

export function isJwkCageError(value) {
  return value instanceof JwkCageError;
}

export function fail(code, detail, context) {
  throw new JwkCageError(code, detail, context);
}
