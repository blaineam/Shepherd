// The Overview's Software card: wording for the self-update state
// (docs/UPDATE.md). Pure, so test/update.test.js covers it without a DOM.
import { fmtBytes } from './weight.js';

// updateLine says where this Shepherd stands against the latest release.
export function updateLine(u) {
  const s = (u && u.status) || null;
  if (!u || !u.enabled || !s) return { tone: 'muted', text: 'Update checks are off ([update] in shepherd.toml).' };
  if (s.applying) return { tone: 'warn', text: 'Installing ' + (s.latest_version || 'the update') + ' and restarting…' };
  if (s.applied) return { tone: 'good', text: s.applied + ' is installed; Shepherd is restarting into it.' };
  if (s.last_error && !s.latest_version) return { tone: 'warn', text: 'Could not check for updates: ' + s.last_error };
  if (!s.latest_version) return { tone: 'muted', text: 'Not checked yet.' };
  if (!s.available) return { tone: 'good', text: 'Up to date (' + s.current + ').' };
  return { tone: 'warn', text: s.latest_version + ' is available; this is ' + s.current + '.' };
}

// rollbackLine mentions a recent rollback, or nothing.
export function rollbackLine(u) {
  const st = (u && u.status && u.status.state) || {};
  if (st.rolled_back) return 'The last update was rolled back: ' + st.rolled_back + '.';
  if (st.applied && !st.confirmed) return st.applied + ' was installed and is still being confirmed.';
  return '';
}

// dataDirLine words the data directory's size, biggest parts first.
export function dataDirLine(u) {
  const s = (u && u.status) || {};
  const total = Number(s.data_dir_bytes) || 0;
  if (!total) return '';
  const parts = Object.entries(s.data_dir_parts || {}).sort((a, b) => b[1] - a[1]).slice(0, 3)
    .map(([k, v]) => k + ' ' + fmtBytes(v));
  return 'Data on disk: ' + fmtBytes(total) + (parts.length ? ' (' + parts.join(', ') + ')' : '') + '.';
}
