import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These assertions used to pin the vulnerable behaviour of lodash 4.17.10. lodash 4.18.1 fixes
// GHSA-35jh-r3h4-6jhm, GHSA-4xc9-xhrj-v574 and GHSA-xxjr-mmjv-4gpg, so they are inverted to assert
// the attacks are now rejected, and that inversion is the visible evidence of the fix.

test('secure now: mergeLayers with a single layer keeps a constructor.prototype payload away from Object.prototype', () => {
  try {
    const merged = mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));
    assert.equal(Object.hasOwn(Object.prototype, 'charMergeOneLayer'), false);
    assert.equal({}.charMergeOneLayer, undefined);
    assert.equal(merged.charMergeOneLayer, undefined);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact keeps an inherited property for a crafted key path', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);
    assert.equal(Object.hasOwn(Object.prototype, 'charOmitInherited'), true);
    assert.equal({}.charOmitInherited, 'inherited');
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});
