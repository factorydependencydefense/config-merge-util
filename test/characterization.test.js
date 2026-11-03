import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These assertions used to pin the vulnerable behaviour of the pinned lodash build. lodash 4.18.1
// fixes GHSA-4xc9-xhrj-v574 and GHSA-xxjr-mmjv-4gpg, so they now assert the secure behaviour.

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
