import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These assertions pin the vulnerable behaviour of the pinned lodash build. The remediation PR is
// expected to invert them, and that inversion is the visible evidence of the fix.

test('vulnerable today: mergeLayers with a single layer lets a constructor.prototype payload reach Object.prototype', () => {
  try {
    mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));
    assert.equal({}.charMergeOneLayer, 'PWN');
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('vulnerable today: the lodash omit build behind redact deletes an inherited property for a crafted key path', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);
    assert.equal({}.charOmitInherited, undefined);
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});
