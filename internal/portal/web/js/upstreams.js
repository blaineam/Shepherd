// Upstream resolver address validation, presets and ordering. Pure.
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export function isIPv4(s) { return IPV4.test(s); }
export function isIPv6(s) {
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
  let str = s;
  const cut = s.lastIndexOf(':') + 1;
  if (s.slice(cut).includes('.')) { if (!IPV4.test(s.slice(cut))) return false; str = s.slice(0, cut) + '0:0'; }
  const dbl = str.split('::');
  if (dbl.length > 2) return false;
  const parse = (x) => (x === '' ? [] : x.split(':'));
  const all = [...parse(dbl[0]), ...(dbl.length === 2 ? parse(dbl[1]) : [])];
  if (!all.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false;
  return dbl.length === 2 ? all.length <= 7 : all.length === 8;
}
export const isIP = (s) => isIPv4(s) || isIPv6(s);

function validPort(p) { return /^\d{1,5}$/.test(p) && +p >= 1 && +p <= 65535; }

// Splits "host", "host:port", "[v6]:port"; returns null when malformed.
function hostPort(s) {
  if (s.startsWith('[')) {
    const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
    if (!m || !isIPv6(m[1]) || (m[2] && !validPort(m[2]))) return null;
    return { host: m[1], port: m[2] || '', v6: true };
  }
  if (isIPv6(s)) return { host: s, port: '', v6: true, bare6: true };
  const i = s.lastIndexOf(':');
  const host = i < 0 ? s : s.slice(0, i), port = i < 0 ? '' : s.slice(i + 1);
  if (i >= 0 && !validPort(port)) return null;
  if (!host || !(isIPv4(host) || HOST.test(host))) return null;
  return { host, port, v6: false };
}

// Describes what a typed address will become. {ok, kind, hint, error}
export function classifyAddr(input) {
  const s = String(input || '').trim();
  if (!s) return { ok: false, kind: '', error: '', hint: 'Enter an IP, tls://host, https://host/dns-query or tcp://ip' };
  if (/\s/.test(s)) return { ok: false, kind: '', error: 'Addresses cannot contain spaces' };
  const m = /^([a-z]+):\/\/(.*)$/i.exec(s);
  if (!m) {
    const hp = hostPort(s);
    if (!hp) return { ok: false, kind: '', error: 'Not a valid IP address. Use 9.9.9.10, 9.9.9.10:53 or [2001:db8::1]:53' };
    if (hp.bare6) return { ok: false, kind: 'udp', error: 'Wrap an IPv6 address with a port in brackets, like [2001:db8::1]:53' };
    if (!isIP(hp.host)) return { ok: false, kind: '', error: 'Plain DNS needs an IP address. For a hostname use tls://' + hp.host };
    return { ok: true, kind: 'udp', hint: 'Plain DNS over UDP, port ' + (hp.port || '53') + '. Not encrypted.' };
  }
  const scheme = m[1].toLowerCase(), rest = m[2];
  if (scheme === 'tcp') {
    const hp = hostPort(rest);
    if (!hp || !isIP(hp.host)) return { ok: false, kind: 'tcp', error: 'tcp:// needs an IP address, like tcp://9.9.9.10' };
    return { ok: true, kind: 'tcp', hint: 'Plain DNS over TCP, port ' + (hp.port || '53') + '. Not encrypted.' };
  }
  if (scheme === 'tls') {
    const hp = hostPort(rest);
    if (!hp) return { ok: false, kind: 'dot', error: 'tls:// needs a host, like tls://dns.example.net' };
    return { ok: true, kind: 'dot', hint: 'DNS over TLS (DoT), port ' + (hp.port || '853') + '. Encrypted.' };
  }
  if (scheme === 'https') {
    const slash = rest.indexOf('/');
    const hp = hostPort(slash < 0 ? rest : rest.slice(0, slash));
    if (!hp) return { ok: false, kind: 'doh', error: 'https:// needs a host, like https://dns.example.net/dns-query' };
    return { ok: true, kind: 'doh', hint: 'DNS over HTTPS (DoH)' + (slash < 0 ? ', path /dns-query' : '') + '. Encrypted.' };
  }
  return { ok: false, kind: '', error: 'Unsupported scheme "' + scheme + '". Use tls://, https:// or tcp://' };
}

export const KIND_LABEL = { udp: 'UDP', tcp: 'TCP', dot: 'DoT', doh: 'DoH' };
export const isEncrypted = (kind) => kind === 'dot' || kind === 'doh';

// Moves item at `from` to `to` (immutable).
export function move(list, from, to) {
  if (from === to || from < 0 || to < 0 || from >= list.length || to >= list.length) return list;
  const a = [...list];
  a.splice(to, 0, a.splice(from, 1)[0]);
  return a;
}

// Variants of a preset the user can add: plain, DoH, DoT.
export function presetVariants(p) {
  const out = [];
  const plain = Array.isArray(p.plain) ? p.plain.filter(Boolean) : [];
  for (const a of plain.slice(0, 2)) out.push({ kind: 'udp', label: 'Plain ' + a, addr: a });
  if (p.doh) out.push({ kind: 'doh', label: 'DoH', addr: String(p.doh) });
  if (p.dot) out.push({ kind: 'dot', label: 'DoT', addr: /^tls:\/\//i.test(p.dot) ? p.dot : 'tls://' + p.dot });
  return out;
}

export function parseBootstrap(text) {
  const items = String(text || '').split(/[\s,]+/).filter(Boolean);
  const bad = items.filter((x) => !isIP(x.replace(/^\[|\]$/g, '')));
  return { servers: items, bad };
}

export function healthLabel(u) {
  if (u.healthy) return u.rtt_ms ? Math.round(u.rtt_ms) + ' ms' : 'ok';
  return u.consecutive_failures ? 'failing (' + u.consecutive_failures + ')' : 'down';
}
