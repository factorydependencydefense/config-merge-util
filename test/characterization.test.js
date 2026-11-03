import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These assertions used to pin the vulnerable behaviour of the previously pinned lodash build. The
// lodash 4.18.1 upgrade closes both prototype pollution paths, so each one now asserts the attack is
// rejected; that inversion is the visible evidence of the fix.

test('secure now: mergeLayers with a single layer does not let a constructor.prototype payload reach Object.prototype', () => {
  try {
    const merged = mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));

    assert.notEqual({}.charMergeOneLayer, 'PWN');
    assert.equal({}.charMergeOneLayer, undefined);
    assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, 'charMergeOneLayer'), false);
    assert.notEqual(merged.constructor.prototype, Object.prototype);
    assert.equal(Object.prototype.hasOwnProperty.call(merged, 'constructor'), true);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact does not delete an inherited property for a crafted key path', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);

    assert.notEqual({}.charOmitInherited, undefined);
    assert.equal({}.charOmitInherited, 'inherited');
    assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, 'charOmitInherited'), true);
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});
