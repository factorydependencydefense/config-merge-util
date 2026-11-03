import assert from 'node:assert/strict';
import test from 'node:test';
import { mergeLayers, readPath, redact, sameConfig } from '../src/index.js';

const base = { db: { host: 'localhost', port: 5432 }, retries: 3 };

test('mergeLayers builds the whole merged config from three layers', () => {
  assert.deepEqual(mergeLayers(base, { db: { host: 'prod.db' } }, { retries: 5 }), {
    db: { host: 'prod.db', port: 5432 },
    retries: 5,
  });
});

test('mergeLayers keeps the lodash array merge semantics', () => {
  assert.deepEqual(mergeLayers({ a: { b: 1 }, list: [1, 2] }, { a: { c: 2 }, list: [3] }), {
    a: { b: 1, c: 2 },
    list: [3, 2],
  });
});

test('mergeLayers leaves every input layer untouched', () => {
  const first = { db: { host: 'localhost', port: 5432 }, retries: 3 };
  const second = { db: { host: 'prod.db' } };
  mergeLayers(first, second);
  assert.deepEqual(first, { db: { host: 'localhost', port: 5432 }, retries: 3 });
  assert.deepEqual(second, { db: { host: 'prod.db' } });
});

test('redact removes exactly the secret keys', () => {
  assert.deepEqual(
    redact({ user: 'svc', region: 'eu', password: 'hunter2', token: 'abc', privateKey: 'pem' }),
    { user: 'svc', region: 'eu' },
  );
});

test('readPath resolves nested paths and falls back when a segment is missing', () => {
  assert.equal(readPath(base, 'db.port'), 5432);
  assert.equal(readPath(base, 'db.replica.host', 'none'), 'none');
  assert.equal(readPath({ a: {} }, 'a.b.c', 'fallback'), 'fallback');
  assert.equal(readPath(base, 'db.replica.host'), undefined);
});

test('sameConfig compares configs after redaction', () => {
  assert.equal(sameConfig({ a: 1, token: 'x' }, { a: 1, token: 'y' }), true);
  assert.equal(sameConfig({ a: 1 }, { a: 2 }), false);
});
