import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import unset from 'lodash/unset.js';
import { mergeLayers, redact } from '../src/index.js';

// These assertions used to pin the vulnerable behaviour of the pinned lodash build. lodash 4.18.1
// fixes GHSA-4xc9-xhrj-v574, GHSA-xxjr-mmjv-4gpg and GHSA-35jh-r3h4-6jhm, so each one now asserts
// the attack is rejected. That inversion is the visible evidence of the fix.

test('secure now: mergeLayers rejects a single-layer constructor.prototype payload', () => {
  try {
    mergeLayers(JSON.parse('{"constructor":{"prototype":{"charMergeOneLayer":"PWN"}}}'));
    assert.notEqual({}.charMergeOneLayer, 'PWN');
    assert.notEqual('charMergeOneLayer' in Object.prototype, true);
  } finally {
    delete Object.prototype.charMergeOneLayer;
  }
});

test('secure now: the lodash omit build behind redact rejects a crafted __proto__ key path', () => {
  Object.prototype.charOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.charOmitInherited']);
    assert.notEqual({}.charOmitInherited, undefined);
    assert.notEqual('charOmitInherited' in Object.prototype, false);
  } finally {
    delete Object.prototype.charOmitInherited;
  }
});

test('secure now: mergeLayers rejects a nested constructor.prototype payload', () => {
  try {
    mergeLayers(JSON.parse('{"db":{"constructor":{"prototype":{"charMergeNested":"PWN"}}}}'));
    assert.notEqual({}.charMergeNested, 'PWN');
    assert.notEqual('charMergeNested' in Object.prototype, true);
  } finally {
    delete Object.prototype.charMergeNested;
  }
});

test('secure now: mergeLayers rejects a __proto__ layer', () => {
  try {
    mergeLayers(JSON.parse('{"__proto__":{"charMergeProtoKey":"PWN"}}'));
    assert.notEqual({}.charMergeProtoKey, 'PWN');
    assert.notEqual('charMergeProtoKey' in Object.prototype, true);
  } finally {
    delete Object.prototype.charMergeProtoKey;
  }
});

test('secure now: mergeLayers rejects an untrusted constructor.prototype payload over a trusted base', () => {
  try {
    mergeLayers({ retries: 3 }, JSON.parse('{"constructor":{"prototype":{"charMergeTwoLayers":"PWN"}}}'));
    assert.notEqual({}.charMergeTwoLayers, 'PWN');
    assert.notEqual('charMergeTwoLayers' in Object.prototype, true);
  } finally {
    delete Object.prototype.charMergeTwoLayers;
  }
});

test('secure now: redact rejects deletion of an inherited property that shares a secret key name', () => {
  Object.prototype.password = 'inherited';
  try {
    redact({ a: 1 });
    assert.notEqual({}.password, undefined);
    assert.notEqual('password' in Object.prototype, false);
  } finally {
    delete Object.prototype.password;
  }
});

test('secure now: the lodash unset build rejects a crafted __proto__ key path', () => {
  Object.prototype.charUnsetInherited = 'inherited';
  try {
    unset({ a: 1 }, '__proto__.charUnsetInherited');
    assert.notEqual({}.charUnsetInherited, undefined);
    assert.notEqual('charUnsetInherited' in Object.prototype, false);
  } finally {
    delete Object.prototype.charUnsetInherited;
  }
});
