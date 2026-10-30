// Synthetic data for demo mode: devices, groups, the blocking catalog and
// resolver presets. Everything is made up. Addresses come from the RFC 5737 and
// RFC 3849 documentation ranges, hardware addresses use the locally
// administered 02:00:5e prefix, and every domain is under example.com/net/org.
import { mulberry32, hash2 } from './demo.js';
import { TYPES as ALL_TYPES, typeLabel } from './devtypes.js';

export const DEVICE_IPS = ['192.0.2.11', '192.0.2.14', '192.0.2.23', '192.0.2.31', '192.0.2.47', '192.0.2.58', '198.51.100.8', '198.51.100.21', '198.51.100.60'];

export { GROUP_COLORS } from './devtypes.js';

export const DEMO_GROUPS = [
  { id: 'grp-kids', name: 'Kids', color: '#f0b64a' },
  { id: 'grp-family', name: 'Family', color: '#16c7bd' },
  { id: 'grp-guests', name: 'Guests', color: '#6aa6f2' },
  { id: 'grp-iot', name: 'Smart home', color: '#a78bfa' },
  { id: 'grp-work', name: 'Work', color: '#6fcf97' },
];

const VENDORS = ['Aurora', 'Halcyon', 'Brightwave', 'Nimbus', 'Kestrel', 'Orbis', 'Tessel', 'Northwind', 'Lumen', 'Quill'];
const TYPES = ALL_TYPES.filter((t) => t !== 'router/infrastructure');

// [alias, vendor, type, groups, mdns]
const NAMED = [
  ['Living Room TV', 'Aurora', 'tv', ['grp-family'], 'living-room-tv.local'],
  ['Kids Tablet', 'Brightwave', 'tablet', ['grp-kids'], 'kids-tablet.local'],
  ['Work Laptop', 'Northwind', 'laptop', ['grp-work'], 'work-laptop.local'],
  ['Garage Camera', 'Kestrel', 'camera', ['grp-iot'], ''],
  ['Kitchen Speaker', 'Lumen', 'speaker', ['grp-iot', 'grp-family'], 'kitchen-speaker.local'],
  ['Game Console', 'Orbis', 'game console', ['grp-kids'], 'game-console.local'],
  ['Guest Phone', 'Halcyon', 'phone', ['grp-guests'], ''],
  ['Office Printer', 'Quill', 'printer', ['grp-work', 'grp-iot'], 'office-printer.local'],
  ['Hallway Thermostat', 'Tessel', 'smart-home hub', ['grp-iot'], ''],
  ['Bedroom TV', 'Aurora', 'tv', ['grp-family'], 'bedroom-tv.local'],
  ['Parents Phone', 'Halcyon', 'phone', ['grp-family'], 'parents-phone.local'],
  ['Kids Laptop', 'Northwind', 'laptop', ['grp-kids'], 'kids-laptop.local'],
  ['Study Desktop', 'Northwind', 'laptop', ['grp-work'], 'study-desktop.local'],
  ['Backyard Camera', 'Kestrel', 'camera', ['grp-iot'], ''],
  ['Front Door Camera', 'Kestrel', 'camera', ['grp-iot'], ''],
  ['Smart Doorbell', 'Lumen', 'smart-home hub', ['grp-iot'], ''],
  ['Robot Vacuum', 'Tessel', 'smart-home hub', ['grp-iot'], ''],
  ['Guest Tablet', 'Brightwave', 'tablet', ['grp-guests'], ''],
  ['Guest Laptop', 'Nimbus', 'laptop', ['grp-guests'], ''],
  ['Media Server', 'Nimbus', 'laptop', ['grp-family'], 'media-server.local'],
  ['Fitness Watch', 'Halcyon', 'unknown', ['grp-family'], ''],
  ['Baby Monitor', 'Kestrel', 'camera', ['grp-iot'], ''],
  ['Soundbar', 'Lumen', 'speaker', ['grp-family'], ''],
  ['Streaming Stick', 'Aurora', 'tv', ['grp-family'], ''],
  ['Weather Station', 'Tessel', 'smart-home hub', ['grp-iot'], ''],
  ['Garage Door Opener', 'Quill', 'smart-home hub', ['grp-iot'], ''],
  ['Kids Phone', 'Halcyon', 'phone', ['grp-kids'], 'kids-phone.local'],
  ['Spare Tablet', 'Brightwave', 'tablet', [], ''],
  ['Desk Lamp', 'Lumen', 'smart-home hub', ['grp-iot'], ''],
];

export function ipFor(i) {
  if (i < DEVICE_IPS.length) return DEVICE_IPS[i];
  let n = i - DEVICE_IPS.length;
  if (n < 140) return '192.0.2.' + (100 + n);
  n -= 140;
  if (n < 150) return '198.51.100.' + (100 + n);
  n -= 150;
  if (n < 250) return '203.0.113.' + (1 + n);
  n -= 250;
  return '2001:db8:5::' + n.toString(16);
}

export function macFor(i) {
  const h = (n) => ((n >>> 0) & 255).toString(16).padStart(2, '0');
  return '02:00:5e:' + h(i >> 16) + ':' + h(i >> 8) + ':' + h(i);
}

const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

export function fallbackName(d) {
  if (d.alias) return d.alias;
  const n = d.names || {};
  if (n.mdns) return n.mdns.replace(/\.local$/, '').replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  if (n.hostname) return n.hostname;
  if (n.rdns) return n.rdns;
  if (d.vendor) return d.vendor + ' ' + typeLabel(d.type);
  return (d.ips && d.ips[0]) || 'Unknown device';
}

export function buildDevices(count = 38, now = Date.now()) {
  const out = [];
  for (let i = 0; i < count; i++) {
    const rng = mulberry32(hash2(91, i));
    const named = NAMED[i];
    const vendor = named ? named[1] : VENDORS[(rng() * VENDORS.length) | 0];
    const type = named ? named[2] : TYPES[(rng() * (TYPES.length - 1)) | 0];
    const aliasIt = !named && rng() < 0.12;
    const hasMdns = named ? !!named[4] : rng() < 0.35;
    const age = i < 9 ? rng() * 90000 : rng() < 0.6 ? 60000 + rng() * 6 * 3600000 : 6 * 3600000 + rng() * 13 * 86400000;
    const first = now - (3 + rng() * 60) * 86400000;
    const ip = ipFor(i);
    const d = {
      id: 'dev-' + String(i + 1).padStart(4, '0'),
      alias: named ? named[0] : aliasIt ? 'Room ' + (1 + ((rng() * 30) | 0)) + ' ' + typeLabel(type) : '',
      names: {
        mdns: named ? named[4] : hasMdns ? slug(vendor + '-' + type + '-' + i) + '.local' : '',
        hostname: !named && rng() < 0.3 ? slug(type) + '-' + (1000 + i) : '',
        rdns: rng() < 0.25 ? 'host-' + i + '.lan.example.net' : '',
      },
      vendor, type,
      type_reason: named || rng() < 0.7 ? 'Matched on hostname and vendor' : 'Guessed from open services',
      macs: [macFor(i + 1)],
      ips: rng() < 0.15 && !named ? [ip, '2001:db8:5::' + (i + 1).toString(16)] : [ip],
      first_seen: new Date(first).toISOString(),
      last_seen: new Date(now - age).toISOString(),
      groups: named ? [...named[3]] : rng() < 0.2 ? [DEMO_GROUPS[(rng() * 5) | 0].id] : [],
      tags: named && i < 9 ? (i === 6 ? ['guest'] : i === 3 ? ['outdoor'] : []) : rng() < 0.08 ? ['travel'] : [],
      excluded: i === 8 || (!named && rng() < 0.03),
      notes: i === 3 ? 'Mounted above the garage door. Firmware updates are manual.' : '',
    };
    d.name = fallbackName(d);
    // A timed and an untimed wandering device make the mode visible in demos.
    if (i === 5) { d.wandering = true; d.wandering_until = new Date(now + 37 * 60000).toISOString(); }
    if (i === 6 || i === 27) d.wandering = true;
    if (!d.wandering) d.wandering = false;
    out.push(d);
  }
  return out;
}

export const DEVICE_BY_IP = (() => {
  const m = new Map();
  buildDevices(DEVICE_IPS.length).forEach((d) => m.set(d.ips[0], { id: d.id, name: d.name }));
  return m;
})();

// ------------------------------------------------------------------ catalog
export const CATEGORIES = ['Social', 'Messaging and Calls', 'Streaming', 'Gaming', 'Dating', 'Shopping', 'Adult', 'Gambling', 'Ads and Trackers', 'Malware and Phishing'];

const app = (id, name, category, description, n) => ({ id, kind: 'app', name, category, description, license: '', homepage: '', approx_entries: n, recommended: false });
const APPS = [
  app('facebook', 'Facebook', 'Social', 'Feed, groups and marketplace, including its content delivery hosts.', 64),
  app('instagram', 'Instagram', 'Social', 'Photo and video sharing, stories and reels.', 38),
  app('threads', 'Threads', 'Social', 'Short text posts linked to Instagram accounts.', 12),
  app('tiktok', 'TikTok', 'Social', 'Short video feed and its analytics hosts.', 47),
  app('snapchat', 'Snapchat', 'Social', 'Camera messaging, stories and spotlight.', 29),
  app('x-social', 'X', 'Social', 'Short posts and live conversations.', 33),
  app('reddit', 'Reddit', 'Social', 'Forums, communities and embedded media.', 21),
  app('pinterest', 'Pinterest', 'Social', 'Pinboards and shopping pins.', 18),
  { ...app('meta', 'Meta (all apps)', 'Social', 'Everything above from the same company in one switch: Facebook, Instagram, Threads, WhatsApp and Messenger.', 0), includes: ['facebook', 'instagram', 'threads', 'whatsapp', 'messenger'], recommended: true },
  app('whatsapp', 'WhatsApp', 'Messaging and Calls', 'Messaging and calls.', 16),
  app('messenger', 'Messenger', 'Messaging and Calls', 'Chat and video calls linked to Facebook.', 14),
  app('discord', 'Discord', 'Messaging and Calls', 'Voice, video and text communities.', 24),
  app('telegram', 'Telegram', 'Messaging and Calls', 'Cloud messaging, channels and bots.', 11),
  app('youtube', 'YouTube', 'Streaming', 'Video platform, including embedded players.', 41),
  app('netflix', 'Netflix', 'Streaming', 'Subscription movies and series.', 27),
  app('disney', 'Disney+', 'Streaming', 'Subscription family streaming.', 19),
  app('twitch', 'Twitch', 'Streaming', 'Live game streams and chat.', 22),
  app('spotify', 'Spotify', 'Streaming', 'Music and podcasts.', 25),
  app('steam', 'Steam', 'Gaming', 'PC game store, downloads and community.', 36),
  app('epic', 'Epic Games', 'Gaming', 'Game launcher and store.', 20),
  app('roblox', 'Roblox', 'Gaming', 'User-made online games.', 17),
  app('fortnite', 'Fortnite', 'Gaming', 'Online battle game and its services.', 15),
  app('minecraft', 'Minecraft', 'Gaming', 'Sandbox game, realms and marketplace.', 13),
  app('xbox', 'Xbox network', 'Gaming', 'Console online services and party chat.', 23),
  app('psn', 'PlayStation Network', 'Gaming', 'Console online services and store.', 26),
  app('tinder', 'Tinder', 'Dating', 'Swipe-based dating.', 9),
  app('bumble', 'Bumble', 'Dating', 'Dating and friend finding.', 8),
  app('hinge', 'Hinge', 'Dating', 'Relationship-focused dating.', 7),
  app('temu', 'Temu', 'Shopping', 'Discount marketplace and its ad hosts.', 31),
  app('aliexpress', 'AliExpress', 'Shopping', 'Global marketplace.', 28),
  app('ebay', 'eBay', 'Shopping', 'Auctions and listings.', 22),
];

const LIST_BUNDLES = [['Adult', 'adult', ['adult-core']], ['Gambling', 'gambling', ['gambling-core']], ['Ads and Trackers', 'ads', ['core-ads', 'tracker-shield', 'tv-telemetry']], ['Malware and Phishing', 'malware', ['malware-domains', 'phishing-watch', 'scam-sites', 'cryptojacking']]].map(([category, k, includes]) => ({ id: 'cat-' + k, kind: 'category', name: category, category, description: 'Every ' + category.toLowerCase() + ' blocklist in one switch.', license: '', homepage: '', approx_entries: 0, recommended: false, includes }));
const BUNDLES = [['Social', 'social'], ['Messaging and Calls', 'messaging'], ['Streaming', 'streaming'], ['Gaming', 'gaming'], ['Dating', 'dating'], ['Shopping', 'shopping']].map(([category, k]) => ({
  id: 'cat-' + k, kind: 'category', name: 'All ' + category, category, description: 'Every ' + category.toLowerCase() + ' app in the catalog.', license: '', homepage: '', approx_entries: 0, recommended: false,
  includes: APPS.filter((a) => a.category === category && !a.includes).map((a) => a.id),
}));

const lst = (id, name, category, description, license, slugPath, n, recommended = false) => ({ id, kind: 'list', name, category, description, license, homepage: 'https://example.org/lists/' + slugPath, approx_entries: n, recommended });
const LISTS = [
  lst('core-ads', 'Core Ads and Trackers', 'Ads and Trackers', 'A balanced, widely used list of advertising and tracking hosts. Safe for most households.', 'CC0-1.0', 'core-ads', 112000, true),
  lst('tracker-shield', 'Tracker Shield', 'Ads and Trackers', 'Stricter tracker and analytics coverage. May break a few sites that rely on analytics.', 'MIT', 'tracker-shield', 64800),
  lst('tv-telemetry', 'Smart TV Telemetry', 'Ads and Trackers', 'Phone-home and ad hosts used by connected televisions and streaming sticks.', 'GPL-3.0', 'tv-telemetry', 2300),
  lst('malware-domains', 'Malware Domains', 'Malware and Phishing', 'Hosts known to serve malware, ransomware and botnet control.', 'CC-BY-4.0', 'malware-domains', 92400, true),
  lst('phishing-watch', 'Phishing Watch', 'Malware and Phishing', 'Recently reported phishing and scam sites, refreshed often.', 'CC-BY-SA-4.0', 'phishing-watch', 31200, true),
  lst('scam-sites', 'Scam Sites', 'Malware and Phishing', 'Fake shops, tech-support scams and prize traps.', 'MIT', 'scam-sites', 18700),
  lst('cryptojacking', 'Cryptojacking', 'Malware and Phishing', 'Scripts that mine coins in your browser without asking.', 'MIT', 'cryptojacking', 1800),
  lst('adult-core', 'Adult Content', 'Adult', 'Pornography and explicit content hosts.', 'MIT', 'adult-core', 412000),
  lst('gambling-core', 'Gambling', 'Gambling', 'Online casinos, sports betting and lottery sites.', 'MIT', 'gambling-core', 18200),
];

export const DEMO_CATALOG = { entries: [...BUNDLES, ...LIST_BUNDLES, ...APPS, ...LISTS], categories: CATEGORIES };

export const DEMO_SWITCHES = [
  { name: 'apple-private-relay', title: 'Block iCloud Private Relay', description: 'Answers "not found" for the relay hostnames so Apple devices report that Private Relay is unavailable on this network and fall back to normal DNS, which Shepherd can filter.' },
  { name: 'safe-search', title: 'Force SafeSearch', description: 'Steers search engines to their filtered mode for these devices so explicit results are hidden.' },
  { name: 'block-doh-bypass', title: 'Block DNS bypass', description: 'Blocks well-known public encrypted DNS hostnames so a device cannot quietly skip Shepherd.' },
];

export const DEMO_PRESETS = [
  { id: 'alpine', name: 'Alpine DNS', provider: 'Alpine Networks', description: 'Fast public resolver with no filtering and no query logging.', plain: ['203.0.113.10', '203.0.113.11'], doh: 'https://alpine.example.net/dns-query', dot: 'tls://alpine.example.net', filtering: 'none', notes: 'Anycast network, broad regional coverage.' },
  { id: 'meridian', name: 'Meridian Secure', provider: 'Meridian Foundation', description: 'Blocks known malware domains and validates DNSSEC.', plain: ['198.51.100.10', '198.51.100.11'], doh: 'https://meridian.example.org/dns-query', dot: 'tls://meridian.example.org', filtering: 'malware', notes: 'Run by a non-profit.' },
  { id: 'harbor', name: 'Harbor Family', provider: 'Harbor Labs', description: 'Blocks malware and adult content before Shepherd even sees the query.', plain: ['203.0.113.20'], doh: 'https://harbor.example.com/dns-query', dot: 'tls://harbor.example.com', filtering: 'family', notes: 'Overlaps with Shepherd blocklists.' },
  { id: 'tern', name: 'Tern Private', provider: 'Tern Privacy', description: 'Privacy-first resolver that keeps no logs and supports encrypted DNS only.', plain: [], doh: 'https://tern.example.net/dns-query', dot: 'tls://tern.example.net', filtering: 'none', notes: 'No plain DNS endpoint.' },
  { id: 'quartz', name: 'Quartz Ad-Block', provider: 'Quartz', description: 'Public resolver with built-in ad and tracker blocking.', plain: ['203.0.113.30', '203.0.113.31'], doh: 'https://quartz.example.com/dns-query', dot: 'tls://quartz.example.com', filtering: 'ads', notes: 'Double filtering if you also use ad lists here.' },
];
