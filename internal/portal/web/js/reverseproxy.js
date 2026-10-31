// Proxy host validation, backend parsing and certificate wording. Pure.
// The server validates everything again (internal/reverseproxy); this is
// here so a typo is explained while typing instead of after a round trip.
import { isIPv4, isIPv6 } from './upstreams.js';

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

// Mirrors reverseproxy.NormalizeDomain: a real multi-label name, because a
// wildcard certificate can never cover an address or a bare "localhost".
export function validateDomain(input) {
  const d = String(input || '').trim().toLowerCase().replace(/\.$/, '');
  if (!d) return { ok: false, error: 'Enter the public name, like jellyfin.example.com' };
  if (d.length > 253) return { ok: false, error: 'That name is longer than 253 characters' };
  const labels = d.split('.');
  if (labels.length < 2) return { ok: false, error: 'Use a full name with a dot, like app.example.com' };
  if (!labels.every((l) => LABEL.test(l))) return { ok: false, error: 'Only letters, digits, hyphens and dots, with no scheme, port or wildcard' };
  if (/^\d+$/.test(labels[labels.length - 1])) return { ok: false, error: 'That is an address, not a name' };
  return { ok: true, domain: d };
}

function validBackendHost(h) {
  if (isIPv4(h)) return true;
  if (h.length > 253) return false;
  return h.replace(/\.$/, '').split('.').every((l) => LABEL.test(l));
}

// Reads a backend the way people write one: "http://127.0.0.1:8096",
// "127.0.0.1:8096" (http assumed), "https://nas.lan" (default port). A path
// is refused rather than silently dropped: the request's own path is what
// gets forwarded.
export function parseTarget(input) {
  const s = String(input || '').trim();
  if (!s) return { ok: false, error: 'Enter the backend, like http://127.0.0.1:8096' };
  let scheme = 'http';
  let rest = s;
  let explicit = false;
  const m = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i.exec(s);
  if (m) {
    scheme = m[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') return { ok: false, error: 'Backends are reached over http:// or https://' };
    rest = m[2];
    explicit = true;
  }
  rest = rest.replace(/\/$/, '');
  if (rest.includes('@')) return { ok: false, error: 'No credentials or path in the backend address' };
  if (/[/?#]/.test(rest)) return { ok: false, error: 'No path: Shepherd forwards each request\'s own path unchanged' };
  let host;
  let port = '';
  if (rest.startsWith('[')) {
    const b = /^\[([^\]]+)\](?::(\d+))?$/.exec(rest);
    if (!b || !isIPv6(b[1])) return { ok: false, error: 'Not a valid host or IPv6 address' };
    host = b[1];
    port = b[2] || '';
  } else {
    if ((rest.match(/:/g) || []).length > 1) return { ok: false, error: isIPv6(rest) ? 'Wrap an IPv6 host in brackets, like [2001:db8::10]:8080' : 'Not a valid host' };
    const i = rest.lastIndexOf(':');
    host = (i < 0 ? rest : rest.slice(0, i)).toLowerCase();
    port = i < 0 ? '' : rest.slice(i + 1);
    if (!host || !validBackendHost(host)) return { ok: false, error: 'Not a valid host name or address' };
  }
  if (!port) {
    if (!explicit) return { ok: false, error: 'Add the backend\'s port, like 127.0.0.1:8096' };
    port = scheme === 'https' ? '443' : '80';
  }
  const n = /^\d{1,5}$/.test(port) ? Number(port) : 0;
  if (n < 1 || n > 65535) return { ok: false, error: 'The port must be between 1 and 65535' };
  return { ok: true, scheme, host, port: n };
}

export function formatTarget(h) {
  const host = String(h.target_host || '').includes(':') ? '[' + h.target_host + ']' : h.target_host;
  return h.target_scheme + '://' + host + ':' + h.target_port;
}

// Whether the "*.base" certificate covers domain: exactly one label more,
// never the base itself. null when no wildcard is configured (unknown, not
// a problem worth flagging yet).
export function covers(wildcard, domain) {
  if (!wildcard) return null;
  const base = String(wildcard).replace(/^\*\./, '');
  const d = String(domain || '');
  if (!d.endsWith('.' + base)) return false;
  const prefix = d.slice(0, -(base.length + 1));
  return prefix.length > 0 && !prefix.includes('.');
}

// What deserves a badge on a host row, each with a short label and a
// longer explanation for its tooltip.
export function hostWarnings(h, wildcard) {
  const out = [];
  // The server also requests the bare base domain itself alongside the
  // wildcard (docs/REVERSEPROXY.md), which covers() alone does not know
  // about: it answers pure "*.base" coverage only, by design.
  const base = wildcard ? String(wildcard).replace(/^\*\./, '') : '';
  if (h.domain !== base && covers(wildcard, h.domain) === false) {
    out.push({ kind: 'uncovered', label: 'Not covered by ' + wildcard, title: 'The certificate is only valid for one label under the domain, so browsers will refuse this name. Use a name directly under the domain.' });
  }
  if (h.target_scheme === 'https' && h.skip_tls_verify) {
    out.push({ kind: 'noverify', label: 'Backend not verified', title: 'Any certificate from this backend is accepted. Fine for a self-signed backend on this machine or your LAN; anything on the path to it could impersonate it.' });
  }
  return out;
}

export function sortHosts(hosts) {
  return [...(hosts || [])].sort((a, b) => a.domain.localeCompare(b.domain));
}

export function filterHosts(hosts, q) {
  const needle = String(q || '').trim().toLowerCase();
  if (!needle) return hosts;
  return hosts.filter((h) => h.domain.includes(needle) || formatTarget(h).toLowerCase().includes(needle));
}

const DAY = 86400000;

// One line about the listener's certificate, with a tone for its color.
// Renewal starts 30 days before expiry, so fewer days than that left means
// renewals have been failing.
export function certSummary(status, now = Date.now()) {
  if (!status || !status.enabled) return { tone: 'muted', text: 'Listener off' };
  const c = status.certificate;
  if (!c) return { tone: 'warn', text: 'Certificate not obtained yet: HTTPS handshakes fail until it is (see the server log)' };
  const end = Date.parse(c.not_after);
  const days = Math.floor((end - now) / DAY);
  const date = new Date(end).toISOString().slice(0, 10);
  if (days < 0) return { tone: 'bad', text: 'Certificate expired on ' + date };
  if (days < 30) return { tone: 'warn', text: 'Valid ' + days + ' days more, until ' + date + '; renewal is overdue, check the server log' };
  return { tone: 'good', text: 'Valid until ' + date + ' (' + days + ' days)' };
}

// Builds the POST/PUT body from the form, or says which field is wrong.
export function hostBody({ domain, target, skipVerify, enabled }) {
  const d = validateDomain(domain);
  if (!d.ok) return { ok: false, field: 'domain', error: d.error };
  const t = parseTarget(target);
  if (!t.ok) return { ok: false, field: 'target', error: t.error };
  const body = { domain: d.domain, target_scheme: t.scheme, target_host: t.host, target_port: t.port, skip_tls_verify: t.scheme === 'https' && !!skipVerify };
  if (typeof enabled === 'boolean') body.enabled = enabled;
  return { ok: true, body };
}

// The address a browser should open for domain: the listener's port is
// part of it until the owner moves the listener to 443.
export function publicURL(domain, listen) {
  const port = String(listen || '').split(':').pop();
  return 'https://' + domain + (port && port !== '443' ? ':' + port : '') + '/';
}
