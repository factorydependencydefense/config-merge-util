import assert from 'node:assert/strict';
import test from 'node:test';
import { mergeLayers, readPath, redact, sameConfig } from '../src/index.js';

const base = { db: { host: 'localhost', port: 5432 }, retries: 3 };

test('mergeLayers merges deeply, later layers win', () => {
  const merged = mergeLayers(base, { db: { host: 'prod.db' } }, { retries: 5 });
  assert.equal(merged.db.host, 'prod.db');
  assert.equal(merged.db.port, 5432);
  assert.equal(merged.retries, 5);
});

test('mergeLayers does not mutate the first layer', () => {
  mergeLayers(base, { retries: 9 });
  assert.equal(base.retries, 3);
});

test('redact drops secret keys', () => {
  assert.deepEqual(redact({ user: 'svc', password: 'hunter2', token: 'abc' }), { user: 'svc' });
});

test('readPath returns a fallback for missing paths', () => {
  assert.equal(readPath(base, 'db.host'), 'localhost');
  assert.equal(readPath(base, 'db.replica.host', 'none'), 'none');
});

test('sameConfig ignores secret differences', () => {
  assert.equal(sameConfig({ a: 1, token: 'x' }, { a: 1, token: 'y' }), true);
  assert.equal(sameConfig({ a: 1 }, { a: 2 }), false);
});
