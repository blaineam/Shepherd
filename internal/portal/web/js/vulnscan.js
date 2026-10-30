// Pure vulnscan-view helpers: sorting and tooltip text for the
// Vulnerabilities panel in the device drawer (devices.js). No DOM, no
// network — kept separate so they are easy to unit test, the same reason
// internal/portal/web/js/alarms.js exists. Severity presentation itself
// (severityLabel/severityBadgeClass) is reused from alarms.js rather than
// duplicated: a finding's severity is the same five-step scale an alarm's
// severity is (see docs/VULNSCAN.md and docs/ALARMS.md).
import { SEVERITIES } from './alarms.js';

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
