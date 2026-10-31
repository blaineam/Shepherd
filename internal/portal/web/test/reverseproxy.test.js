import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateDomain, parseTarget, formatTarget, covers, sortHosts, filterHosts, certSummary, hostBody, hostWarnings, publicURL,
} from '../js/reverseproxy.js';

test('validateDomain accepts real multi-label names and normalizes them', () => {
  assert.deepEqual(validateDomain('  Jellyfin.Example.COM. '), { ok: true, domain: 'jellyfin.example.com' });
  assert.deepEqual(validateDomain('xn--bcher-kva.example'), { ok: true, domain: 'xn--bcher-kva.example' });
  for (const bad of ['', 'localhost', '*.example.com', 'exa mple.com', 'example.com:443', '-a.example.com', 'a..example.com', '192.0.2.10', 'app.123', 'https://example.com', 'a_b.example.com', 'x'.repeat(64) + '.example.com']) {
    const r = validateDomain(bad);
    assert.equal(r.ok, false, bad);
    assert.ok(r.error, 'an error message for ' + JSON.stringify(bad));
  }
});

test('parseTarget reads the forms people paste from another proxy manager', () => {
  assert.deepEqual(parseTarget('http://127.0.0.1:8096'), { ok: true, scheme: 'http', host: '127.0.0.1', port: 8096 });
  assert.deepEqual(parseTarget(' HTTPS://NAS.lan:5001/ '), { ok: true, scheme: 'https', host: 'nas.lan', port: 5001 });
  assert.deepEqual(parseTarget('127.0.0.1:2283'), { ok: true, scheme: 'http', host: '127.0.0.1', port: 2283 });
  assert.deepEqual(parseTarget('https://192.0.2.5'), { ok: true, scheme: 'https', host: '192.0.2.5', port: 443 });
  assert.deepEqual(parseTarget('http://jellyfin'), { ok: true, scheme: 'http', host: 'jellyfin', port: 80 });
  assert.deepEqual(parseTarget('[2001:db8::10]:8080'), { ok: true, scheme: 'http', host: '2001:db8::10', port: 8080 });
  assert.deepEqual(parseTarget('https://[2001:db8::10]'), { ok: true, scheme: 'https', host: '2001:db8::10', port: 443 });
});

test('parseTarget explains what is wrong', () => {
  const cases = {
    '': /backend/i,
    '127.0.0.1': /port/i,
    'ftp://192.0.2.1:21': /http/i,
    'http://127.0.0.1:0': /port/i,
    'http://127.0.0.1:70000': /port/i,
    'http://127.0.0.1:80/sub/path': /path/i,
    'http://user:pw@127.0.0.1:80': /path|credentials/i,
    'http://bad host:80': /host/i,
    '[2001:db8::1': /host/i,
  };
  for (const [input, re] of Object.entries(cases)) {
    const r = parseTarget(input);
    assert.equal(r.ok, false, input);
    assert.match(r.error, re, input);
  }
});

test('formatTarget round-trips through parseTarget', () => {
  const hosts = [
    { target_scheme: 'http', target_host: '127.0.0.1', target_port: 8096 },
    { target_scheme: 'https', target_host: '2001:db8::10', target_port: 8443 },
  ];
  assert.equal(formatTarget(hosts[0]), 'http://127.0.0.1:8096');
  assert.equal(formatTarget(hosts[1]), 'https://[2001:db8::10]:8443');
  for (const h of hosts) {
    const p = parseTarget(formatTarget(h));
    assert.deepEqual([p.scheme, p.host, p.port], [h.target_scheme, h.target_host, h.target_port]);
  }
});

test('covers matches exactly one label under the wildcard, and is unknown without one', () => {
  assert.equal(covers('*.example.com', 'jellyfin.example.com'), true);
  assert.equal(covers('*.example.com', 'a.b.example.com'), false);
  assert.equal(covers('*.example.com', 'example.com'), false);
  assert.equal(covers('*.example.com', 'jellyfin.example.net'), false);
  assert.equal(covers('*.example.com', 'badexample.com'), false);
  assert.equal(covers('', 'jellyfin.example.com'), null);
  assert.equal(covers(undefined, 'jellyfin.example.com'), null);
});

test('hostWarnings names everything that will surprise someone', () => {
  const base = { domain: 'jellyfin.example.com', target_scheme: 'http', enabled: true };
  assert.deepEqual(hostWarnings(base, '*.example.com'), []);
  assert.deepEqual(hostWarnings({ ...base, domain: 'a.b.example.com' }, '*.example.com').map((w) => w.kind), ['uncovered']);
  // The server also requests the bare base domain itself alongside the
  // wildcard (docs/REVERSEPROXY.md), so a host pointed directly at it is
  // covered too, even though covers() alone (pure "*.base" matching) says no.
  assert.deepEqual(hostWarnings({ ...base, domain: 'example.com' }, '*.example.com'), []);
  assert.deepEqual(hostWarnings({ ...base, target_scheme: 'https', skip_tls_verify: true }, '').map((w) => w.kind), ['noverify']);
  for (const w of hostWarnings({ ...base, domain: 'x.y.example.com', target_scheme: 'https', skip_tls_verify: true }, '*.example.com')) {
    assert.ok(w.label && w.title, 'each warning has a label and an explanation');
  }
});

test('sortHosts orders by domain without touching the input', () => {
  const input = [{ domain: 'b.example.com' }, { domain: 'a.example.com' }, { domain: 'c.example.com' }];
  assert.deepEqual(sortHosts(input).map((h) => h.domain), ['a.example.com', 'b.example.com', 'c.example.com']);
  assert.equal(input[0].domain, 'b.example.com');
  assert.deepEqual(sortHosts(null), []);
});

test('filterHosts matches the public name or the backend', () => {
  const hosts = [
    { domain: 'jellyfin.example.com', target_scheme: 'http', target_host: '127.0.0.1', target_port: 8096 },
    { domain: 'git.example.com', target_scheme: 'https', target_host: 'forge.lan', target_port: 3443 },
  ];
  assert.equal(filterHosts(hosts, '').length, 2);
  assert.deepEqual(filterHosts(hosts, 'JELLY').map((h) => h.domain), ['jellyfin.example.com']);
  assert.deepEqual(filterHosts(hosts, 'forge').map((h) => h.domain), ['git.example.com']);
  assert.deepEqual(filterHosts(hosts, ':8096').map((h) => h.domain), ['jellyfin.example.com']);
  assert.equal(filterHosts(hosts, 'nothing').length, 0);
});

test('certSummary covers off, pending, healthy, renewing-soon and expired', () => {
  const now = Date.parse('2026-10-30T00:00:00Z');
  assert.equal(certSummary({ enabled: false }, now).tone, 'muted');
  assert.match(certSummary({ enabled: true, certificate: null }, now).text, /not obtained yet/i);
  const ok = certSummary({ enabled: true, certificate: { names: ['*.example.com'], not_after: '2026-12-29T00:00:00Z' } }, now);
  assert.equal(ok.tone, 'good');
  assert.match(ok.text, /60 days/);
  const soon = certSummary({ enabled: true, certificate: { names: ['*.example.com'], not_after: '2026-11-10T00:00:00Z' } }, now);
  assert.equal(soon.tone, 'warn');
  assert.match(soon.text, /11 days/);
  const gone = certSummary({ enabled: true, certificate: { names: ['*.example.com'], not_after: '2026-10-01T00:00:00Z' } }, now);
  assert.equal(gone.tone, 'bad');
  assert.match(gone.text, /expired/i);
});

test('hostBody turns the form into exactly what the API accepts', () => {
  assert.deepEqual(hostBody({ domain: ' Jellyfin.Example.com ', target: 'http://127.0.0.1:8096', skipVerify: true }), {
    ok: true, body: { domain: 'jellyfin.example.com', target_scheme: 'http', target_host: '127.0.0.1', target_port: 8096, skip_tls_verify: false },
  });
  assert.deepEqual(hostBody({ domain: 'nas.example.com', target: 'https://192.0.2.5:5001', skipVerify: true, enabled: false }), {
    ok: true, body: { domain: 'nas.example.com', target_scheme: 'https', target_host: '192.0.2.5', target_port: 5001, skip_tls_verify: true, enabled: false },
  });
  const badDomain = hostBody({ domain: 'nope', target: 'http://127.0.0.1:80' });
  assert.deepEqual([badDomain.ok, badDomain.field], [false, 'domain']);
  const badTarget = hostBody({ domain: 'a.example.com', target: '127.0.0.1' });
  assert.deepEqual([badTarget.ok, badTarget.field], [false, 'target']);
});

test('publicURL adds the listener port unless it is the standard one', () => {
  assert.equal(publicURL('jellyfin.example.com', ':443'), 'https://jellyfin.example.com/');
  assert.equal(publicURL('jellyfin.example.com', '[::]:443'), 'https://jellyfin.example.com/');
  assert.equal(publicURL('jellyfin.example.com', ':8443'), 'https://jellyfin.example.com:8443/');
  assert.equal(publicURL('jellyfin.example.com', '192.0.2.1:9443'), 'https://jellyfin.example.com:9443/');
  assert.equal(publicURL('jellyfin.example.com', ''), 'https://jellyfin.example.com/');
});
