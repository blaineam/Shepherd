import test from 'node:test';
import assert from 'node:assert/strict';
import { createApi, ApiError } from '../js/api.js';

function res(status, body, text) {
  return { status, ok: status >= 200 && status < 300, statusText: 'ST', json: async () => body, text: async () => text ?? '' };
}

test('sends the CSRF header and credentials and parses JSON', async () => {
  let seen;
  const api = createApi({ fetchFn: async (p, o) => { seen = [p, o]; return res(200, { ok: 1 }); } });
  assert.deepEqual(await api('/api/status'), { ok: 1 });
  assert.equal(seen[1].headers['X-Shepherd'], '1');
  assert.equal(seen[1].credentials, 'same-origin');
  await api('/api/rules', { method: 'POST', headers: { 'X-Extra': 'y' }, body: '{}' });
  assert.equal(seen[1].headers['X-Extra'], 'y');
  assert.equal(seen[1].headers['X-Shepherd'], '1');
});

test('401 calls onUnauthorized and throws', async () => {
  let called = 0;
  const api = createApi({ fetchFn: async () => res(401), onUnauthorized: () => { called++; } });
  await assert.rejects(api('/api/status'), (e) => e instanceof ApiError && e.status === 401 && e.message === 'unauthorized');
  assert.equal(called, 1);
});

test('errors carry status and body text; 202 and 204 return null', async () => {
  const api = createApi({ fetchFn: async (p) => (p === '/a' ? res(404, null, 'not found\n') : p === '/b' ? res(202) : p === '/d' ? res(204) : res(500, null, '')) });
  await assert.rejects(api('/a'), (e) => e.status === 404 && e.message === 'not found');
  assert.equal(await api('/b'), null);
  assert.equal(await api('/d'), null);
  await assert.rejects(api('/c'), (e) => e.status === 500 && e.message === 'ST');
});
