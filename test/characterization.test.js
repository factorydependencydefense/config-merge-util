import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These assertions used to pin the vulnerable behaviour of lodash 4.17.10. lodash 4.18.1 fixes
// GHSA-35jh-r3h4-6jhm, GHSA-4xc9-xhrj-v574 and GHSA-xxjr-mmjv-4gpg, so each one is inverted to
// assert the attack is now rejected, and that inversion is the visible evidence of the fix.

test('secure now: mergeLayers with a single layer rejects a constructor.prototype payload', () => {
  try {
    const merged = mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));
    assert.notEqual({}.charMergeOneLayer, 'PWN');
    assert.notEqual(merged.charMergeOneLayer, 'PWN');
    assert.equal(Object.hasOwn(Object.prototype, 'charMergeOneLayer'), false);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact rejects a crafted key path that targets an inherited property', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);
    assert.notEqual({}.charOmitInherited, undefined);
    assert.equal({}.charOmitInherited, 'inherited');
    assert.equal(Object.hasOwn(Object.prototype, 'charOmitInherited'), true);
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});
