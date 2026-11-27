import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { auditJwk } from '../src/index.mjs';
import { RSA_PRIVATE, RSA_PUBLIC, cloneKey } from './helpers.mjs';

const kidUnit = fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789');
const safeKidPart = fc.string({ unit: kidUnit, minLength: 1, maxLength: 16 });
const fuzzOptions = { seed: 20261127, numRuns: 100 };

test('fast-check valid public RSA keys with safe generated kids audit safe', () => {
  fc.assert(fc.property(safeKidPart, (part) => {
    const key = { ...cloneKey(RSA_PUBLIC), kid: 'rsa-' + part };
    const report = auditJwk(key);
    assert.equal(report.safe, true, 'valid key was unsafe: ' + report.findings.map((finding) => finding.code).join(','));
    assert.equal(report.findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high'), false);
  }), fuzzOptions);
});

test('fast-check private RSA material in a public key is always a high or critical finding', () => {
  fc.assert(fc.property(fc.constantFrom('d', 'p', 'q'), (parameter) => {
    const key = { ...cloneKey(RSA_PUBLIC), [parameter]: RSA_PRIVATE[parameter] };
    const report = auditJwk(key);
    assert.equal(report.safe, false, 'private material was accepted');
    assert.equal(report.findings.some((finding) => finding.code === 'PRIVATE_MATERIAL_PRESENT'), true);
  }), fuzzOptions);
});

test('fast-check hostile kid injection patterns are never safe', () => {
  fc.assert(fc.property(
    fc.constantFrom('../escape', 'key\\escape', 'key\ninjected', 'key\x00nul', "key';drop", 'key|shell'),
    (kid) => {
      const report = auditJwk({ ...cloneKey(RSA_PUBLIC), kid });
      assert.equal(report.safe, false, 'hostile kid was accepted: ' + JSON.stringify(kid));
      assert.equal(report.findings.some((finding) => finding.code.startsWith('KID_')), true);
    }
  ), fuzzOptions);
});
