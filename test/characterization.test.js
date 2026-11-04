import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers } from '../src/index.js';

// These two assertions used to pin the vulnerable behaviour of lodash 4.17.10, one per attack
// vector. lodash 4.18.1 fixes GHSA-35jh-r3h4-6jhm, GHSA-4xc9-xhrj-v574 and GHSA-xxjr-mmjv-4gpg, so
// each one is inverted to assert that the same attack is now rejected. That inversion is the visible
// evidence of the fix: on 4.17.10 each payload below landed on Object.prototype and these
// assertions fail, on 4.18.1 the payload is refused and they pass.

test('secure now: mergeLayers with a single layer rejects a constructor.prototype payload instead of reaching Object.prototype', () => {
  try {
    const merged = mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));

    // The attack is rejected: the payload never becomes a property every object inherits.
    assert.notEqual({}.charMergeOneLayer, 'PWN');
    assert.notEqual(Object.prototype.charMergeOneLayer, 'PWN');
    assert.equal(Object.hasOwn(Object.prototype, 'charMergeOneLayer'), false);
    assert.throws(() => assert.equal({}.charMergeOneLayer, 'PWN'), assert.AssertionError);

    // The route the attack used is severed: `constructor` stays inert own data on the result and no
    // longer resolves to the real Object constructor or the real prototype.
    assert.notEqual(merged.constructor, Object);
    assert.notEqual(merged.constructor.prototype, Object.prototype);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact rejects a crafted key path instead of deleting an inherited property', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);

    // The attack is rejected: the crafted path no longer unsets anything off Object.prototype.
    assert.notEqual({}.charOmitInherited, undefined);
    assert.equal({}.charOmitInherited, 'inherited');
    assert.equal(Object.hasOwn(Object.prototype, 'charOmitInherited'), true);
    assert.throws(() => assert.equal({}.charOmitInherited, undefined), assert.AssertionError);
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});
