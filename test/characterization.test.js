import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers, redact } from '../src/index.js';

// These assertions used to pin the vulnerable behaviour of the pinned lodash build. lodash 4.18.1
// fixes GHSA-4xc9-xhrj-v574 and GHSA-xxjr-mmjv-4gpg, so they now pin the secure behaviour instead.
// That inversion is the visible evidence of the fix.

test('secure now: mergeLayers with a single layer does not let a constructor.prototype payload reach Object.prototype', () => {
  try {
    mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));
    assert.equal({}.charMergeOneLayer, undefined);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact keeps an inherited property for a crafted key path', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);
    assert.equal({}.charOmitInherited, 'inherited');
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});

test('secure now: mergeLayers with a nested constructor.prototype payload does not reach Object.prototype', () => {
  try {
    mergeLayers(JSON.parse('{"db":{"constructor":{"prototype":{"charMergeNested":"PWN"}}}}'));
    assert.equal({}.charMergeNested, undefined);
  } finally {
    delete Object.prototype.charMergeNested;
  }
});

test('secure now: mergeLayers with a __proto__ layer does not reach Object.prototype', () => {
  try {
    mergeLayers(JSON.parse('{"__proto__":{"charMergeProtoKey":"PWN"}}'));
    assert.equal({}.charMergeProtoKey, undefined);
  } finally {
    delete Object.prototype.charMergeProtoKey;
  }
});

test('secure now: redact keeps an inherited property that shares a secret key name', () => {
  Object.prototype.password = 'inherited';
  try {
    redact({ a: 1 });
    assert.equal({}.password, 'inherited');
  } finally {
    delete Object.prototype.password;
  }
});
