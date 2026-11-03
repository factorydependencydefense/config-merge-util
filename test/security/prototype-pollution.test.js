import assert from 'node:assert/strict';
import test from 'node:test';
import omit from 'lodash/omit.js';
import { mergeLayers, redact } from '../../src/index.js';

test('mergeLayers must not let a single untrusted layer reach Object.prototype', () => {
  try {
    mergeLayers(JSON.parse('{"constructor":{"prototype":{"secMergeOneLayer":"PWN"}}}'));
    assert.equal({}.secMergeOneLayer, undefined);
  } finally {
    delete Object.prototype.secMergeOneLayer;
  }
});

test('mergeLayers must not let an untrusted layer over a trusted base reach Object.prototype', () => {
  try {
    mergeLayers({ retries: 3 }, JSON.parse('{"constructor":{"prototype":{"secMergeTwoLayers":"PWN"}}}'));
    assert.equal({}.secMergeTwoLayers, undefined);
  } finally {
    delete Object.prototype.secMergeTwoLayers;
  }
});

test('mergeLayers must not let a nested untrusted layer reach Object.prototype', () => {
  try {
    mergeLayers(JSON.parse('{"db":{"constructor":{"prototype":{"secMergeNested":"PWN"}}}}'));
    assert.equal({}.secMergeNested, undefined);
  } finally {
    delete Object.prototype.secMergeNested;
  }
});

test('mergeLayers must not let a __proto__ layer reach Object.prototype', () => {
  try {
    mergeLayers(JSON.parse('{"__proto__":{"secMergeProtoKey":"PWN"}}'));
    assert.equal({}.secMergeProtoKey, undefined);
  } finally {
    delete Object.prototype.secMergeProtoKey;
  }
});

test('the lodash omit build behind redact must not delete an inherited property for a crafted key path', () => {
  Object.prototype.secOmitInherited = 'inherited';
  try {
    omit({ a: 1 }, ['__proto__.secOmitInherited']);
    assert.equal({}.secOmitInherited, 'inherited');
  } finally {
    delete Object.prototype.secOmitInherited;
  }
});

test('redact must not delete an inherited property that shares a secret key name', () => {
  Object.prototype.password = 'inherited';
  try {
    redact({ a: 1 });
    assert.equal({}.password, 'inherited');
  } finally {
    delete Object.prototype.password;
  }
});
