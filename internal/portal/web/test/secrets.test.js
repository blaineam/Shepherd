import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TLS_MODES, portForMode, sourceText, usedByText, dnsProviderSummary, tokenBody, relayStatus, relayBody, passwordPlaceholder,
} from '../js/secrets.js';

test('portForMode suggests the usual port without overwriting one the owner typed', () => {
  assert.equal(portForMode('tls', 587), 465);
  assert.equal(portForMode('starttls', 465), 587);
  assert.equal(portForMode('none', ''), 25);
  assert.equal(portForMode('tls', 2525), 2525);
  assert.deepEqual(TLS_MODES.map(([m]) => m), ['starttls', 'tls', 'none']);
});

test('sourceText says where a secret came from, never what it is', () => {
  assert.equal(sourceText(null), '');
  assert.equal(sourceText({ configured: false }), '');
  assert.equal(sourceText({ configured: true, source: 'portal', updated_at: '2026-10-30T12:00:00Z' }), 'Saved in the portal on 2026-10-30');
  assert.match(sourceText({ configured: true, source: 'shepherd.toml', updated_at: '2026-10-30T12:00:00Z' }), /^Imported from shepherd\.toml on 2026-10-30; edit it here/);
  assert.equal(sourceText({ configured: false, source: 'portal', updated_at: '2026-10-31T00:00:00Z' }), 'Removed in the portal on 2026-10-31');
  assert.equal(sourceText({ configured: true, source: 'portal' }), 'Saved in the portal');
});

test('usedByText names the features that issue certificates with the token', () => {
  assert.match(usedByText([]), /Nothing uses it yet/);
  assert.match(usedByText(undefined), /Nothing uses it yet/);
  assert.equal(usedByText(['tls', 'reverseproxy']), 'Used for the portal\'s own HTTPS ([tls]) and the reverse proxy\'s wildcard certificate.');
  assert.equal(usedByText(['future']), 'Used for future.');
});

test('dnsProviderSummary warns only when something is waiting on a token', () => {
  assert.deepEqual(dnsProviderSummary({ configured: true, used_by: [] }), { tone: 'good', text: 'Token set' });
  assert.equal(dnsProviderSummary({ configured: false, used_by: ['reverseproxy'] }).tone, 'warn');
  assert.equal(dnsProviderSummary({ configured: false, used_by: [] }).tone, 'muted');
  assert.equal(dnsProviderSummary(null).tone, 'muted');
});

test('tokenBody trims and refuses what cannot be a token', () => {
  assert.deepEqual(tokenBody('  abc123  '), { ok: true, body: { provider: 'cloudflare', api_token: 'abc123' } });
  assert.deepEqual(tokenBody('t', 'other').body.provider, 'other');
  for (const bad of ['', '   ', 'two words', 'line\nbreak', 'x'.repeat(2049)]) {
    const r = tokenBody(bad);
    assert.equal(r.ok, false, JSON.stringify(bad));
    assert.ok(r.error);
  }
});

test('relayStatus explains each state', () => {
  assert.match(relayStatus({ enabled: false }).text, /turned off/);
  assert.equal(relayStatus({ enabled: true, configured: false }).tone, 'warn');
  assert.deepEqual(relayStatus({ enabled: true, configured: true, active: true, host: 'smtp.example.com', port: 587, tls: 'starttls' }), { tone: 'good', text: 'Sending through smtp.example.com:587 (STARTTLS)' });
  assert.equal(relayStatus(null).tone, 'muted');
});

const form = (o = {}) => ({ host: 'smtp.example.com', port: '587', username: 'shepherd@example.com', password: 'pw', from: 'shepherd@example.com', tls: 'starttls', ...o });

test('relayBody builds the body and sends a password only when one was typed', () => {
  assert.deepEqual(relayBody(form(), null), { ok: true, body: { host: 'smtp.example.com', port: 587, username: 'shepherd@example.com', from: 'shepherd@example.com', tls: 'starttls', password: 'pw' } });
  const current = { configured: true, password_set: true, host: 'smtp.example.com', username: 'shepherd@example.com' };
  const keep = relayBody(form({ password: '' }), current);
  assert.equal(keep.ok, true);
  assert.equal('password' in keep.body, false, 'a blank password keeps the saved one');
  const cleared = relayBody(form({ password: '', username: '', clearPassword: true }), current);
  assert.equal(cleared.body.clear_password, true);
  assert.equal(relayBody(form({ password: 'spaces are fine' }), null).body.password, 'spaces are fine');
});

test('relayBody will not reuse a saved password for a different server', () => {
  const current = { configured: true, password_set: true, host: 'smtp.example.com', username: 'shepherd@example.com' };
  for (const change of [{ host: 'mail.example.net' }, { username: 'other@example.com' }]) {
    const r = relayBody(form({ password: '', ...change }), current);
    assert.equal(r.ok, false);
    assert.equal(r.field, 'password');
    assert.match(r.error, /password again/);
  }
  assert.equal(relayBody(form({ password: '', host: 'mail.example.net', username: '' }), current).ok, true, 'no username: no password to reuse');
});

test('relayBody explains every field it refuses', () => {
  const cases = {
    host: [{ host: '' }, { host: 'smtp://smtp.example.com' }, { host: 'smtp.example.com:587' }, { host: 'bad host' }, { host: '-x.example.com' }],
    port: [{ port: '' }, { port: '0' }, { port: '70000' }, { port: '58.7' }, { port: 'abc' }],
    tls: [{ tls: 'ssl' }],
    username: [{ username: 'a b' }],
    from: [{ from: '' }, { from: 'shepherd' }, { from: 'a b@example.com' }],
    password: [{ password: 'a\nb' }],
  };
  for (const [field, list] of Object.entries(cases)) {
    for (const o of list) {
      const r = relayBody(form(o), null);
      assert.equal(r.ok, false, JSON.stringify(o));
      assert.equal(r.field, field, JSON.stringify(o));
      assert.ok(r.error);
    }
  }
  assert.equal(relayBody({ host: 'relay.example.net', port: 25, from: 'a@example.com' }, null).body.tls, 'starttls', 'TLS defaults to STARTTLS');
});

test('passwordPlaceholder is the only hint a password is saved', () => {
  assert.match(passwordPlaceholder({ password_set: true }), /Saved/);
  assert.doesNotMatch(passwordPlaceholder({ password_set: false }), /Saved/);
  assert.doesNotMatch(passwordPlaceholder(null), /Saved/);
});
