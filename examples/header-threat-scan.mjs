/* Example: scanning hostile JWT headers for injection and confusion attacks. */
import { auditJwtHeader } from '../src/index.mjs';

const attacks = [
  { label: 'alg none bypass', header: { alg: 'none', typ: 'JWT' } },
  { label: 'hmac confusion against rsa keys', header: { alg: 'HS256', kid: 'rsa-1' } },
  { label: 'inline key injection', header: { alg: 'RS256', jwk: { kty: 'RSA', n: 'attacker', e: 'AQAB' } } },
  { label: 'metadata ssrf', header: { alg: 'RS256', jku: 'https://169.254.169.254/latest/meta-data/jwks' } },
  { label: 'obfuscated loopback', header: { alg: 'RS256', jku: 'https://2130706433/jwks.json' } },
  { label: 'kid sql injection', header: { alg: 'RS256', kid: "1' UNION SELECT secret--" } },
  { label: 'kid path traversal', header: { alg: 'RS256', kid: '../../../etc/passwd' } }
];

for (const { label, header } of attacks) {
  const report = auditJwtHeader(header, { expectedKty: 'RSA', algorithms: ['RS256', 'PS256'] });
  console.log(label.padEnd(38), 'blocked:', !report.safe, '|', report.findings.map((hit) => hit.code).slice(0, 2).join(', '));
}
