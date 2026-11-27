/* Example: auditing a JWKS before trusting it as a key source. */
import { auditJwks } from '../src/index.mjs';

const untrustedJwks = {
  keys: [
    {
      kty: 'RSA',
      n: 'qS8LtpU9ZPCikjq9IU_uA-DNFh96zsm5ETOQSpHtlTesZ_ppEc-QC7vzqHCZSN6C82aMqUTmlQ63Zrhrk2is63Cv2Usm3vRD4GIBrQW6dUXas8jG13b7y2M4T4emmT07Aad2-QOxblcid9gPhqXy-MU3iFA0beaULD-WGefvjo0zkzpXfvC-6MrpMon-PFJq3qY8-I4rtSYNDE7JEqAOvKc60ZU6WYcLMfmvxs5ja2A-2PfoeIx99f6wWY2lSsFdHedx4sktkfhhhcX2_641r-ex9ZMQ20SV-ee4kkQVO4iRaHPCroGSJVmFHvRD688qf2u75PxhDAx0Kqg7VtmMeQ',
      e: 'AQAB',
      kid: 'key-one'
    },
    {
      kty: 'EC',
      crv: 'P-256',
      x: 'XZLnr4a5ulO5Li9QUtrVf4HMVttSVF9XMMA0Bch6Yko',
      y: 'iQE4OpBu21sqlgFYAt3NvKrYkq-Ii8GlQ1BGbWOWZgs',
      kid: 'key-one',
      d: 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    }
  ]
};

const report = auditJwks(untrustedJwks);
console.log('safe to trust:', report.safe);
for (const hit of report.findings) {
  console.log(hit.severity.padEnd(9), hit.code.padEnd(30), hit.field);
}
if (!report.safe) {
  console.log('verdict: refuse to fetch or cache this keyset; it leaks private material and has colliding kids');
}
