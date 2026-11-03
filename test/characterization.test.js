import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These assertions pinned the vulnerable behaviour of the previously pinned lodash build. The
// lodash 4.18.1 upgrade closes both prototype pollution paths, so each one now asserts that the
// attack is rejected rather than that it succeeds.

test('secure now: mergeLayers with a single layer rejects a constructor.prototype payload', () => {
  try {
    mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));
    assert.notEqual({}.charMergeOneLayer, 'PWN');
    assert.equal(Object.hasOwn(Object.prototype, 'charMergeOneLayer'), false);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact rejects a crafted __proto__ key path', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);
    assert.notEqual({}.charOmitInherited, undefined);
    assert.equal(Object.hasOwn(Object.prototype, 'charOmitInherited'), true);
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});
