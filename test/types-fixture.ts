import {
  auditJwk,
  auditJwks,
  auditJwtHeader,
  computeJwkThumbprint,
  parseJwk,
  selectVerificationKey,
  stripPrivateMaterial
} from '../types/index.js';
import type { AuditReport, JwkObject } from '../types/index.js';

const key: JwkObject = parseJwk({ kty: 'RSA', n: 'x', e: 'y' });
const report: AuditReport = auditJwk(key);
const safe: boolean = report.safe;
auditJwks({ keys: [key] }, { requireKid: true });
auditJwtHeader({ alg: 'RS256' }, { algorithms: ['RS256'], expectedKty: 'RSA', kind: 'jws' });
const selected: JwkObject = selectVerificationKey({ keys: [key] }, { alg: 'RS256' }, { algorithms: ['RS256'] });
const stripped: JwkObject = stripPrivateMaterial(selected);
const thumbprint: string = computeJwkThumbprint(stripped, 'sha256');
console.log(safe, thumbprint.length);
