// Pure vulnscan-view helpers: sorting and tooltip text for the
// Vulnerabilities panel in the device drawer (devices.js). No DOM, no
// network — kept separate so they are easy to unit test, the same reason
// internal/portal/web/js/alarms.js exists. Severity presentation itself
// (severityLabel/severityBadgeClass) is reused from alarms.js rather than
// duplicated: a finding's severity is the same five-step scale an alarm's
// severity is (see docs/VULNSCAN.md and docs/ALARMS.md).
import { SEVERITIES } from './alarms.js?v=fa35f297';

const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

// severityRank orders a finding's severity the same way alarms does
// (info < low < medium < high < critical); an unknown value sorts lowest.
export function severityRank(sev) {
  return sev in SEVERITY_RANK ? SEVERITY_RANK[sev] : -1;
}

// sortFindings orders findings worst-first (critical at the top), then by
// port, then by name, for a stable, predictable panel order.
export function sortFindings(findings) {
  return [...(findings || [])].sort((a, b) => {
    const r = severityRank(b.severity) - severityRank(a.severity);
    if (r !== 0) return r;
    if (a.port !== b.port) return a.port - b.port;
    return (a.name || '').localeCompare(b.name || '');
  });
}

// activeFindings/resolvedFindings split a device's findings for display:
// active ones are the panel's main content, resolved ones are worth
// showing (so "this was exposed and is now fixed" stays visible, the same
// philosophy internal/vulnscan.Finding documents) but clearly secondary.
export function activeFindings(findings) {
  return sortFindings((findings || []).filter((f) => f.active));
}
export function resolvedFindings(findings) {
  return sortFindings((findings || []).filter((f) => !f.active));
}

// findingTooltip builds the hover text for one finding: its evidence, and,
// for a resolved one, when it cleared.
export function findingTooltip(f) {
  if (!f) return '';
  const parts = [];
  if (f.evidence) parts.push(f.evidence);
  if (!f.active && f.resolved_at) parts.push('Resolved ' + new Date(f.resolved_at).toLocaleString());
  return parts.join(' — ');
}

// flattenFindings turns GET /api/vulnscan/devices's per-device findings list
// into one flat, sorted row per (device, finding) pair — the shape the
// Vulnerabilities page (vulnscanview.js) lists, the same way the Alarms
// screen lists one row per alarm rather than grouping by device first.
// Worst severity first, then device name, then sortFindings' own tie-break
// (port, then name), so the most urgent thing on the whole network always
// leads regardless of which device it is on.
export function flattenFindings(devices) {
  const rows = [];
  for (const d of devices || []) {
    for (const f of sortFindings(d.findings || [])) {
      rows.push({ deviceId: d.device_id, deviceName: d.name || d.device_id, ip: d.ip, lastScanned: d.last_scanned, finding: f });
    }
  }
  rows.sort((a, b) => {
    const r = severityRank(b.finding.severity) - severityRank(a.finding.severity);
    if (r !== 0) return r;
    return (a.deviceName || '').localeCompare(b.deviceName || '');
  });
  return rows;
}

// matchRow filters one flattenFindings() row against the Vulnerabilities
// page's filter state: a minimum severity, active-only/resolved-only/either,
// and free text over the device, finding name, description and evidence.
// Pure so the filtering itself is unit-testable without a DOM.
export function matchRow(row, { severity = '', state = '', text = '' } = {}) {
  const f = row.finding;
  if (severity && severityRank(f.severity) < severityRank(severity)) return false;
  if (state === 'active' && !f.active) return false;
  if (state === 'resolved' && f.active) return false;
  if (text) {
    const needle = text.toLowerCase();
    const hay = [row.deviceName, row.ip, f.name, f.description, f.evidence].filter(Boolean).join('\n').toLowerCase();
    if (!hay.includes(needle)) return false;
  }
  return true;
}

// scanSummary describes a POST /api/vulnscan/scan result for a toast: how
// many devices were (re)scanned and how many findings are currently active
// across them, the same "what changed" framing bulkSummary gives alarms.
export function scanSummary(result) {
  const devices = (result && Array.isArray(result.devices)) ? result.devices : [];
  const active = devices.reduce((n, d) => n + activeFindings(d.findings).length, 0);
  const scanned = devices.length;
  return 'Scanned ' + scanned + ' device' + (scanned === 1 ? '' : 's') + ' — ' + active + ' active finding' + (active === 1 ? '' : 's');
}

// feedSummary describes GET /api/vulnscan's signature set and feed status
// in one line for the Vulnerabilities page header: how many signatures
// are built in versus supplied by the feed, when the feed itself was last
// built upstream, and whether the last fetch failed. `now` is injectable
// for tests. Returns {text, tone} where tone is '' (fine), 'warn' (the feed
// is configured but has never been fetched, or its last fetch failed) or
// 'off' (no feed configured).
export function feedSummary(status, now = Date.now()) {
  const builtin = Number(status && status.builtin_signatures) || 0;
  const fromFeed = Number(status && status.feed_signatures) || 0;
  const feed = status && status.feed;
  const sigs = builtin + ' built-in signature' + (builtin === 1 ? '' : 's');
  if (!feed) return { text: sigs + ' · signature feed off', tone: 'off' };
  const parts = [sigs + ' + ' + fromFeed + ' from the feed'];
  if (feed.generated_at) parts.push('feed built ' + relTimeOf(feed.generated_at, now));
  if (feed.last_error) {
    parts.push('last check failed' + (feed.last_checked ? ' ' + relTimeOf(feed.last_checked, now) : ''));
    return { text: parts.join(' · '), tone: 'warn' };
  }
  if (feed.last_checked) parts.push('checked ' + relTimeOf(feed.last_checked, now));
  else parts.push('not fetched yet');
  return { text: parts.join(' · '), tone: feed.last_checked ? '' : 'warn' };
}

// relTimeOf is a tiny "3h ago" formatter over an ISO timestamp, kept here
// (rather than importing ui.js's relTime) so this module stays DOM-free
// and unit-testable in node.
function relTimeOf(iso, now) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return 'at an unknown time';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return m + 'm ago';
  const h = Math.round(m / 60);
  if (h < 48) return h + 'h ago';
  return Math.round(h / 24) + 'd ago';
}
