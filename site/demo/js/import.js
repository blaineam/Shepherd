// Pure helpers for the device import UI (eero + CSV): validating the login
// and code steps, and summarizing a dry-run or applied report for display.
// No DOM; see importview.js for that.

const MAX_LOGIN = 256;
const MAX_CODE = 32;
const CONTROL_RE = /[\x00-\x1f\x7f]/;

export function validLogin(s) {
  const v = String(s || '').trim();
  return v.length > 0 && v.length <= MAX_LOGIN && !CONTROL_RE.test(v);
}

export function validCode(s) {
  const v = String(s || '').trim();
  return v.length > 0 && v.length <= MAX_CODE && !CONTROL_RE.test(v);
}

// Ordered rows a report can show, skipped when zero.
const REPORT_ROWS = [
  ['created', 'Devices to create'],
  ['matched_by_mac', 'Matched by MAC'],
  ['matched_by_ip', 'Matched by IP'],
  ['updated', 'Devices updated'],
  ['named', 'Names set'],
  ['renamed', 'Names replaced'],
  ['groups_created', 'Groups to create'],
  ['memberships_added', 'Group memberships added'],
  ['tags_added', 'Devices tagged'],
  ['marked_excluded', 'Devices excluded'],
  ['notes_set', 'Notes added'],
  ['types_set', 'Types set'],
  ['skipped', 'Skipped'],
  ['unchanged', 'Already up to date'],
];

// Turns a report (from any /api/import/*/preview or /apply response) into
// ordered {label, count} rows, leaving out anything that happened zero times.
export function reportRows(report) {
  if (!report) return [];
  return REPORT_ROWS.filter(([k]) => Number(report[k]) > 0).map(([k, label]) => ({ label, count: report[k] }));
}

export function reportTitle(report) {
  if (!report) return '';
  if (!report.changed) return report.dry_run ? 'Nothing would change.' : 'Nothing changed.';
  return report.dry_run ? 'Here is what would change:' : 'Done. Here is what changed:';
}
