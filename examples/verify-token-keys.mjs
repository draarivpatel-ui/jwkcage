/* Example: fail-closed verification key selection for a JWT header. */
import { auditJwtHeader, auditJwks, selectVerificationKey } from '../src/index.mjs';

const trustedJwks = {
  keys: [
    {
      kty: 'RSA',
      n: 'qS8LtpU9ZPCikjq9IU_uA-DNFh96zsm5ETOQSpHtlTesZ_ppEc-QC7vzqHCZSN6C82aMqUTmlQ63Zrhrk2is63Cv2Usm3vRD4GIBrQW6dUXas8jG13b7y2M4T4emmT07Aad2-QOxblcid9gPhqXy-MU3iFA0beaULD-WGefvjo0zkzpXfvC-6MrpMon-PFJq3qY8-I4rtSYNDE7JEqAOvKc60ZU6WYcLMfmvxs5ja2A-2PfoeIx99f6wWY2lSsFdHedx4sktkfhhhcX2_641r-ex9ZMQ20SV-ee4kkQVO4iRaHPCroGSJVmFHvRD688qf2u75PxhDAx0Kqg7VtmMeQ',
      e: 'AQAB',
      alg: 'RS256',
      use: 'sig',
      kid: 'rsa-2024-01'
    }
  ]
};

const header = { alg: 'RS256', kid: 'rsa-2024-01', typ: 'JWT' };

const jwksReport = auditJwks(trustedJwks);
console.log('keyset safe:', jwksReport.safe);

const headerReport = auditJwtHeader(header, { algorithms: ['RS256'], expectedKty: 'RSA' });
console.log('header safe:', headerReport.safe);

const key = selectVerificationKey(trustedJwks, header, { algorithms: ['RS256'] });
console.log('selected verification key kid:', key.kid);
console.log('private material in selected key:', 'd' in key ? 'present (bad)' : 'absent (correct)');
