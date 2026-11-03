// DHCP mode's wording and validation. Pure: no DOM, no network.
//
// The server validates everything again (internal/dhcp), and it is the
// authority. This is here so a typo is explained while someone is typing it
// rather than after a round trip.

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

// The three ranges a LAN may use, for the message somebody reads when they
// have typed a public one by mistake. RFC 1918's own prefixes.
const RFC1918 = '10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16'; // leakcheck:allow

// normalizeMAC mirrors dhcp.NormalizeMAC: any spelling of six hex pairs
// becomes lowercase, colon-separated. Empty means it is not a MAC address.
export function normalizeMAC(input) {
  const hex = String(input || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) return '';
  return hex.match(/../g).join(':');
}

export function isMAC(input) { return MAC_RE.test(String(input || '').toLowerCase()); }

// parseIPv4 returns the four octets, or null. Deliberately strict: no
// shorthand, no leading zeros, because "192.0.2.010" is a different address in
// some resolvers and a typo in all of them.
export function parseIPv4(input) {
  const s = String(input || '').trim();
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const out = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p[0] === '0')) return null;
    const n = Number(p);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

const toInt = (octets) => ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;

// inRange reports whether ip falls between start and end inclusive. All three
// are strings; a value that is not an address is never in range.
export function inRange(ip, start, end) {
  const a = parseIPv4(ip);
  const s = parseIPv4(start);
  const e = parseIPv4(end);
  if (!a || !s || !e) return false;
  const n = toInt(a);
  return toInt(s) <= n && n <= toInt(e);
}

// inSubnet reports whether ip is inside a CIDR prefix like "192.0.2.0/24".
export function inSubnet(ip, cidr) {
  const a = parseIPv4(ip);
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(String(cidr || '').trim());
  if (!a || !m) return false;
  const base = parseIPv4(m[1]);
  const bits = Number(m[2]);
  if (!base || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (toInt(a) & mask) === (toInt(base) & mask);
}

// validateReservation checks one reservation against the current addressing.
// settings is the screen's `settings` object. An empty address is allowed: a
// reservation can hold only a name.
export function validateReservation({ mac, ip, hostname, note }, settings = {}) {
  const m = normalizeMAC(mac);
  if (!m) return { ok: false, field: 'mac', error: 'Enter the device\'s MAC address, as six hex pairs like 02:00:5e:01:02:03' };
  const name = String(hostname || '').trim();
  if (name.length > 63) return { ok: false, field: 'hostname', error: 'A hostname is limited to 63 characters' };
  if (name && !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(name)) {
    return { ok: false, field: 'hostname', error: 'A hostname may hold letters, digits and hyphens, and may not start or end with a hyphen' };
  }
  const n = String(note || '').trim();
  if (n.length > 200) return { ok: false, field: 'note', error: 'A note is limited to 200 characters' };

  const addr = String(ip || '').trim();
  if (!addr) return { ok: true, value: { mac: m, ip: '', hostname: name, note: n } };
  if (!parseIPv4(addr)) return { ok: false, field: 'ip', error: 'Enter an IPv4 address, or leave it empty to reserve only a name' };
  if (settings.subnet && !inSubnet(addr, settings.subnet)) {
    return { ok: false, field: 'ip', error: addr + ' is not inside the LAN ' + settings.subnet };
  }
  if (settings.server_ip === addr) return { ok: false, field: 'ip', error: addr + ' is Shepherd\'s own address' };
  if (settings.gateway === addr) return { ok: false, field: 'ip', error: addr + ' is the router\'s own address' };
  const out = { ok: true, value: { mac: m, ip: addr, hostname: name, note: n } };
  // An address inside the dynamic pool is allowed and is the ordinary case:
  // pinning a device to the address it already holds. The allocator takes a
  // reserved address out of the pool walk for everyone else, so it can only
  // go to the device it names. Worth saying, not worth refusing.
  if (settings.pool_start && inRange(addr, settings.pool_start, settings.pool_end)) {
    out.note = addr + ' is inside the pool Shepherd hands out from (' + settings.pool_start + '–' + settings.pool_end
      + '). That is fine — it is simply held back from everyone else — but shrinking the pool past it is tidier.';
  }
  return out;
}

// validateRange checks a chosen LAN range before it is sent. The server
// checks it again, and then checks it against the network as it is, which is
// the part that cannot be done here.
export function validateRange({ subnet, server_ip: serverIP, gateway, pool_start: poolStart, pool_end: poolEnd }) {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(String(subnet || '').trim());
  if (!m || !parseIPv4(m[1])) return { ok: false, field: 'subnet', error: 'Enter the range in CIDR form, like 192.0.2.0/24' };
  const bits = Number(m[2]);
  if (bits < 16 || bits > 30) return { ok: false, field: 'subnet', error: 'The prefix must be between /16 and /30' };
  const cidr = m[1] + '/' + bits;
  if (!isPrivateV4(m[1])) {
    return { ok: false, field: 'subnet', error: 'A LAN uses a private range: ' + RFC1918 };
  }
  const fields = [
    ['server_ip', serverIP, 'Shepherd\'s own address in the new range'],
    ['gateway', gateway, 'the router\'s address in the new range'],
    ['pool_start', poolStart, 'the first address to hand out'],
    ['pool_end', poolEnd, 'the last address to hand out'],
  ];
  const value = { subnet: cidr };
  for (const [key, raw, label] of fields) {
    const v = String(raw || '').trim();
    if (!v) return { ok: false, field: key, error: 'Enter ' + label };
    if (!parseIPv4(v)) return { ok: false, field: key, error: label[0].toUpperCase() + label.slice(1) + ' must be an IPv4 address' };
    if (!inSubnet(v, cidr)) return { ok: false, field: key, error: v + ' is not inside ' + cidr };
    value[key] = v;
  }
  if (value.server_ip === value.gateway) {
    return { ok: false, field: 'gateway', error: 'Shepherd and the router cannot share one address' };
  }
  if (!inRange(value.pool_end, value.pool_start, value.pool_end) || !inRange(value.pool_start, value.pool_start, value.pool_end)) {
    return { ok: false, field: 'pool_end', error: 'The pool must start at or below where it ends' };
  }
  for (const [key, label] of [['server_ip', 'Shepherd\'s own address'], ['gateway', 'the router\'s address']]) {
    if (inRange(value[key], value.pool_start, value.pool_end)) {
      return { ok: false, field: key, error: label[0].toUpperCase() + label.slice(1) + ' is inside the pool, so it could be handed to a device' };
    }
  }
  return { ok: true, value };
}

// isPrivateV4 mirrors netip.Addr.IsPrivate: a LAN is one of the three
// ranges RFC 1918 set aside, and nothing else.
export function isPrivateV4(ip) {
  const o = parseIPv4(ip);
  if (!o) return false;
  if (o[0] === 10) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  return o[0] === 192 && o[1] === 168;
}

// suggestRange fills a range form from a chosen prefix, following the
// convention nearly every home router uses: the router on .1, this host just
// above it, and the pool well clear of both.
export function suggestRange(cidr, current = {}) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.\d+\/(\d{1,2})$/.exec(String(cidr || '').trim());
  if (!m) return null;
  const bits = Number(m[4]);
  if (bits !== 24) return null; // the only shape this convention fits
  const base = m[1] + '.' + m[2] + '.' + m[3] + '.';
  return {
    subnet: base + '0/24',
    gateway: base + '1',
    server_ip: current.server_ip && inSubnet(current.server_ip, base + '0/24') ? current.server_ip : base + '2',
    pool_start: base + '100',
    pool_end: base + '200',
  };
}

// conflictTone maps a conflict's severity to the screen's tone classes.
export function conflictTone(severity) { return severity === 'blocking' ? 'bad' : 'warn'; }

// rangeSummary is the one line above the conflicts: what is in force, and
// whether anything is stopping the chosen range.
export function rangeSummary(rangeView, conflicts) {
  const r = rangeView || {};
  const list = conflicts || [];
  if (!r.chosen) {
    const cur = (r.current && r.current.subnet) || 'the interface\'s own range';
    return { tone: 'muted', text: 'Using ' + cur + ', which comes from shepherd.toml and this host\'s interface. Choose a range below to use a different one.' };
  }
  const blocking = list.filter((c) => c.severity === 'blocking');
  if (blocking.length) {
    return {
      tone: 'bad',
      text: 'Chosen: ' + r.subnet + '. Shepherd will not serve it yet — ' + blocking.length
        + (blocking.length === 1 ? ' thing has' : ' things have') + ' to change first.',
    };
  }
  if (list.length) return { tone: 'warn', text: 'Chosen: ' + r.subnet + '. It fits, with notes.' };
  return { tone: 'good', text: 'Chosen: ' + r.subnet + '. It fits the network as it is.' };
}

// reservedLabel words the per-device reserved switch.
export function reservedLabel(res) {
  if (!res) return null;
  if (res.on) {
    return res.ip
      ? { on: true, text: 'Pinned to ' + res.ip + (res.in_pool ? ', held back from the pool for this device' : '') }
      : { on: true, text: 'Reserved by name only' };
  }
  if (res.candidate) return { on: false, text: 'Pin this device to ' + res.candidate + ', so it keeps that address' };
  return { on: false, text: 'No address to pin yet: Shepherd has not seen one for this device' };
}

// modeLabel is how each mode reads on the screen.
export function modeLabel(mode) {
  switch (mode) {
    case 'observe': return 'Watching';
    case 'serve': return 'Serving';
    default: return 'Off';
  }
}

// stateSummary turns the status into one line and a tone, which is what the
// top of the screen says. It is the answer to "what is this doing right now",
// and it never says "on" when something is stopping it.
export function stateSummary(d) {
  const s = (d && d.status) || {};
  if (d && d.available === false) return { tone: 'muted', text: 'DHCP mode is not configured in shepherd.toml.' };
  if (s.mode === 'off') return { tone: 'muted', text: 'Off. Shepherd serves no leases and routes nothing. Reservations below are saved and take effect when it is turned on.' };
  if (s.mode === 'observe') {
    return {
      tone: 'good',
      text: 'Watching only. Shepherd is listening to this network\'s DHCP and cannot answer: the connection it opened has no way to send. '
        + 'Everything below is what it would have done.',
    };
  }
  if (!s.serving) return { tone: 'warn', text: 'Not serving: ' + (s.blocked || 'waiting') + '.' };
  if (s.routing) return { tone: 'good', text: 'Serving, and routing ' + s.routed_count + ' device' + (s.routed_count === 1 ? '' : 's') + ' through Shepherd.' };
  if (s.routing_blocked) return { tone: 'warn', text: 'Serving, but not routing: ' + s.routing_blocked + '.' };
  return { tone: 'good', text: 'Serving every lease with the router\'s own address as the gateway. Nothing is on Shepherd\'s data path.' };
}

// consequences is the plainly worded account of what turning this on does.
// It is a list rather than a paragraph because each line is a separate thing
// that can go wrong, and because the one about the router's own DHCP is the
// step somebody will otherwise forget.
export function consequences(settings = {}) {
  const gw = settings.gateway || 'your router';
  const lease = settings.lease_seconds ? Math.round(settings.lease_seconds / 60) : 10;
  return [
    {
      title: 'Your router\'s DHCP must be off',
      body: 'Two DHCP servers on one network hand out addresses unpredictably — some devices would take Shepherd\'s offer and some '
        + gw + '\'s, differently after every reboot. Shepherd refuses to serve while it can still hear another server answering, '
        + 'so you can set this to Serving first and turn the router\'s DHCP off afterwards.',
    },
    {
      title: 'Routing is a second, separate switch',
      body: 'Serving on its own changes nothing about how traffic flows: every lease carries ' + gw + '\'s own address as the gateway. '
        + 'Only when routing is turned on does traffic start crossing Shepherd.',
    },
    {
      title: 'Routed devices are behind two NATs',
      body: 'Shepherd translates to ' + gw + ', which translates to the internet. Port forwards on ' + gw + ' stop reaching a routed '
        + 'device, UPnP and NAT-PMP requests from one go nowhere, and a game console\'s NAT type gets worse. Consoles are left on '
        + gw + ' unless you turn that off deliberately.',
    },
    {
      title: 'Shepherd becomes load-bearing for routed devices',
      body: 'If Shepherd stops, a routed device has no way out until it comes back. If Shepherd is running but unhealthy it stops '
        + 'claiming to be the gateway, and devices move back to ' + gw + ' within about ' + lease + ' minutes on their own. '
        + 'The kill switch does the same thing immediately and on purpose.',
    },
    {
      title: 'If this host goes down, so does DHCP',
      body: 'Devices keep the addresses they hold and keep working, but nothing hands out new ones, and a lease that runs out is not '
        + 'renewed. Leases are ' + lease + ' minutes, so the network starts to notice in about that long. Turning your router\'s DHCP '
        + 'back on is the recovery, and it needs nothing from Shepherd.',
    },
    {
      title: 'IPv6 is untouched',
      body: 'Shepherd sends no router advertisements and no DHCPv6; ' + gw + ' stays the IPv6 router. That keeps Thread and Matter gear '
        + 'out of harm\'s way, and it means a routed device\'s IPv6 traffic does not pass through Shepherd and is not measured.',
    },
  ];
}

// sortLeases puts the interesting ones first: routed, then active, then by
// address, with expired leases last. An expired lease is shown rather than
// hidden, because it is how a device that has gone away is told from one that
// never had an address.
export function sortLeases(leases) {
  const key = (l) => {
    const ip = parseIPv4(l.ip);
    return [l.expired ? 1 : 0, l.routed ? 0 : 1, ip ? toInt(ip) : 0xffffffff];
  };
  return [...(leases || [])].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] - kb[i];
    return String(a.mac).localeCompare(String(b.mac));
  });
}

// filterLeases matches a typed query against everything on a lease row.
export function filterLeases(leases, query) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return leases || [];
  return (leases || []).filter((l) => [l.mac, l.ip, l.hostname, l.vendor_class, l.device_id, l.reason]
    .some((v) => String(v || '').toLowerCase().includes(q)));
}

// leaseBody is the request shape for a reservation taken from a lease, so
// "reserve this address" is pre-filled with what the device already holds.
export function leaseBody(lease) {
  return { mac: normalizeMAC(lease && lease.mac), ip: (lease && lease.ip) || '', hostname: (lease && lease.hostname) || '', note: '' };
}

// originLabel says where a lease came from. An observed lease is one another
// server handed out, which is the whole point of watching before serving.
export function originLabel(origin) {
  return origin === 'observed' ? 'from your router' : 'from Shepherd';
}
