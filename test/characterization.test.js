import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These assertions used to pin the vulnerable behaviour of the previously pinned lodash build. The
// lodash 4.18.1 upgrade fixes both prototype pollution paths, so they now assert the secure
// behaviour; that inversion is the visible evidence of the fix.

test('secure now: mergeLayers with a single layer does not let a constructor.prototype payload reach Object.prototype', () => {
  try {
    mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));
    assert.equal({}.charMergeOneLayer, undefined);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact does not delete an inherited property for a crafted key path', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);
    assert.equal({}.charOmitInherited, 'inherited');
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});
