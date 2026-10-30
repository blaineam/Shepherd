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
