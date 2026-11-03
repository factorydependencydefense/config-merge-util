import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These two assertions used to pin the vulnerable behaviour of the pinned lodash build: merge
// walked into Object.prototype via constructor.prototype (GHSA-4xc9-xhrj-v574) and omit unset an
// inherited property through a __proto__ key path (GHSA-xxjr-mmjv-4gpg). lodash 4.18.1 fixes both,
// so each test now runs the same attack and asserts that it is rejected.

test('secure now: mergeLayers rejects a constructor.prototype payload instead of reaching Object.prototype', () => {
  try {
    const merged = mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));

    assert.notEqual({}.charMergeOneLayer, 'PWN');
    assert.notEqual(Object.prototype.charMergeOneLayer, 'PWN');
    assert.equal(Object.hasOwn(Object.prototype, 'charMergeOneLayer'), false);
    assert.equal(merged.charMergeOneLayer, undefined);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact rejects a crafted __proto__ key path instead of deleting an inherited property', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);

    assert.notEqual({}.charOmitInherited, undefined);
    assert.equal(Object.hasOwn(Object.prototype, 'charOmitInherited'), true);
    assert.equal({}.charOmitInherited, 'inherited');
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});
