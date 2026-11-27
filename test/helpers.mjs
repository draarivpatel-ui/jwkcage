/* Shared fixtures: real generated key material plus matrix-test utilities. */
import assert from 'node:assert/strict';
import { test } from 'node:test';

export const RSA_PUBLIC = Object.freeze({
  kty: 'RSA',
  n: 'qS8LtpU9ZPCikjq9IU_uA-DNFh96zsm5ETOQSpHtlTesZ_ppEc-QC7vzqHCZSN6C82aMqUTmlQ63Zrhrk2is63Cv2Usm3vRD4GIBrQW6dUXas8jG13b7y2M4T4emmT07Aad2-QOxblcid9gPhqXy-MU3iFA0beaULD-WGefvjo0zkzpXfvC-6MrpMon-PFJq3qY8-I4rtSYNDE7JEqAOvKc60ZU6WYcLMfmvxs5ja2A-2PfoeIx99f6wWY2lSsFdHedx4sktkfhhhcX2_641r-ex9ZMQ20SV-ee4kkQVO4iRaHPCroGSJVmFHvRD688qf2u75PxhDAx0Kqg7VtmMeQ',
  e: 'AQAB',
  alg: 'RS256',
  use: 'sig',
  kid: 'rsa-test-1'
});

export const RSA_PRIVATE = Object.freeze({
  ...RSA_PUBLIC,
  d: 'F_AxLxd0xWiLCDfJdQIzQlc3jY7MuJ-wUO_D1dlKDZgADAJRhZSh5BcnBclQ1w-s5bW352d5XNPlPWKQzh28gd_C8fMBQAC97ezQIeQyms9Uf6XEBM6wF_olCJPADeStCbHhUqCkJWGs3dozcDDg7TQyhFYc5QQAKTaiDW5U5g13s1wBwbhlUDjWDY0rvznw3GfjrVv7GDxVZeAe3pTzI2biIIkTVT-LGJ-FbNg8__jx-3Ts8h8klcHJTSwmLSK7V4wTBJjmZHIYmw3UWrm4B7ZRWf-cmOWdPylkjF8eZC6kdOMEWpqWB-D2sOeUC587X4Tql-BGc7zfWWnyYapLRQ',
  p: '2GsSyWnKBG3H8bYo5CK6zJ3jjfUPJ5LQMjvFAT-kuJTjeb5eeBrreOCYDy2S9lZPNV6VyY8-erlDi-4IzoZx-Xsq8rEJRs7xeQgscqb-xs5uq1TEvxzcU8ipv1slktvOFemo-VBk7HGtepviB-g4MGYLujDYjBFK9uTBIkrltls',
  q: 'yCBnrtUEFKfXXh47r6n1QkG7zqT6p89rbQsUEju6VGgIgjraHPrdC8Gyg702oHQCNpq9w9WeVGCG7429OwAG0yH-RNCFGUXtEQqMleqyZNHkjbNb3ykaQ8Wq3Rcara5aMvT-C9QF79BbG--IJTuRtEKcp_yOjTp90nXgJYIXiLs',
  dp: 'iIfcPUbJFMwxRJMX7vzd_fJpuYftfJjJUbeVTHlbMLt1Wru3m2vYO9Ts-T5WJaRDqja2pocA8qloLKIJ2kjFJJAIgz0ezhYGDsYSTG5_8uoOtXXv_WV2tkC0ni0hYinbNMXJPSfz05rPx7cJ_NUKhbYLFfZ01sCeG24rTbgUfVs',
  dq: 'pLanH6qLdUS_aeOQVICaMDJSFT6MX1nEnTclCezG63nEpwsxQfDnxilieDNfpqhUugSac3h6nA_mf3w1Zz4aX-P2l0TYh3iaKhB4rVtCAOEQL-CTmRUHXQhwHRBLEPATpSUngyy6xirDEjcP4zUoMykwLsMbwPmHXZVPKw_rtsk',
  qi: '1NCmjmMwgsDtYFQVbj9_hKy6ldXkal4auW-9LZ9zQWFHwv_QqTOFP7GQv5XfLCYllN0uwRxAMoZebxZMWr_aLIbR5hPhEK5T94_xcS1eeLllM4gGs7lRcb4Rzf8mFHAWgATq_UUeN9dDzdzxiEp1vZZemKSHD0JM4-fjJq3HYJU'
});

export const EC_PUBLIC = Object.freeze({
  kty: 'EC',
  crv: 'P-256',
  x: 'S-9aV0QIqaT8Epgpifg_Py5oennvh1xkWYicAldZCZ8',
  y: '7JMwOharzFE2SMiPhEObwyAL-nInqjhUzzWt7_8VuuM',
  alg: 'ES256',
  use: 'sig',
  kid: 'ec-test-1'
});

export const ED_PUBLIC = Object.freeze({
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'VMzVWEWGSYiduKvk54z-WBJBykog38_57DMIrkem7fc',
  alg: 'EdDSA',
  use: 'sig',
  kid: 'ed-test-1'
});

export const RFC7638_RSA = Object.freeze({
  kty: 'RSA',
  n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  e: 'AQAB',
  alg: 'RS256',
  kid: '2011-04-29'
});

export const RFC7638_THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

export function symmetricKey(byteLength) {
  return Buffer.from(Array.from({ length: byteLength }, (_unused, index) => (index * 19 + 7) % 256)).toString('base64url');
}

export const OCT_KEY = Object.freeze({
  kty: 'oct',
  k: symmetricKey(32),
  alg: 'HS256',
  use: 'sig',
  kid: 'oct-test-1'
});

export function cloneKey(key) {
  return JSON.parse(JSON.stringify(key));
}

export function publicJwks(keys) {
  return { keys: keys.map(cloneKey) };
}

export function matrix(name, cases, run) {
  for (const testCase of cases) {
    test(name + ' :: ' + testCase.name, () => {
      run(testCase);
    });
  }
}

export function expectUnsafe(report, code) {
  assert.equal(report.safe, false, 'report should be unsafe');
  assert.ok(
    report.findings.some((hit) => hit.code === code),
    'expected finding ' + code + ', got: ' + report.findings.map((hit) => hit.code).join(', ')
  );
}

export function expectSafe(report) {
  assert.equal(report.safe, true, 'expected safe, got findings: ' + report.findings.map((hit) => hit.code).join(', '));
}

export function expectNoFinding(report, code) {
  assert.ok(!report.findings.some((hit) => hit.code === code), 'unexpected finding ' + code);
}
