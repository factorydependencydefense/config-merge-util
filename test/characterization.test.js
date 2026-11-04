import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These two assertions used to pin the vulnerable behaviour of the previously pinned lodash build:
// one per prototype pollution path (merge through `constructor.prototype`, omit through a
// `__proto__.x` key path). The lodash 4.18.1 upgrade closes both, so each is inverted here and now
// asserts the attack is rejected. That inversion is the visible evidence of the fix.

test('secure now: mergeLayers with a single layer rejects a constructor.prototype payload', () => {
  try {
    const merged = mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));

    assert.notEqual({}.charMergeOneLayer, 'PWN');
    assert.equal({}.charMergeOneLayer, undefined);
    assert.equal(Object.hasOwn(Object.prototype, 'charMergeOneLayer'), false);
    // The vulnerable build resolved `constructor` to the real Object constructor and wrote through
    // it; the payload is now contained as plain own data on the result.
    assert.notEqual(merged.constructor, Object);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact rejects a crafted __proto__ key path', () => {
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
