// Pure helpers for the Device names card on the Router screen
// (namesyncview.js): one name per device across Shepherd and everything
// connected. Nothing here touches the DOM.

const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

// labelOf writes a source id the way the screen does.
export function labelOf(report, id) {
  const s = ((report || {}).sources || []).find((x) => x.id === id);
  return s ? s.label : id;
}

// WHY says, for each reason the server gives, why a name was chosen.
const WHY = {
  first: (from) => 'the most readable name, from ' + from,
  edit: (from) => 'renamed on ' + from,
  catchup: () => 'catching up with the agreed name',
};

// changeLine is one device's change as a row: the name it gets, why, what
// it is called now in each place, and where the name goes.
export function changeLine(change, report) {
  const c = change || {};
  const lab = (id) => labelOf(report, id);
  const why = (WHY[c.reason] || (() => ''))(lab(c.from));
  const was = Object.entries(c.names || {})
    .filter(([, name]) => name !== c.name)
    .map(([id, name]) => lab(id) + ': ' + (name || 'no name'));
  const failed = Object.entries(c.failed || {}).map(([id, msg]) => lab(id) + ' refused it: ' + msg);
  return {
    name: c.name || '',
    why,
    was: was.join(' · '),
    to: (c.writes || []).map(lab).join(', '),
    held: (c.held || []).map(lab).join(', '),
    failed: failed.join(' · '),
  };
}

// reportSummary is a preview or a finished run in one sentence, with a tone.
export function reportSummary(report) {
  const r = report || {};
  const broken = (r.sources || []).filter((s) => s.error);
  const bits = [];
  if (r.dry_run) {
    if (r.written) bits.push(plural(r.written, 'name', 'names') + ' would be written');
  } else if (r.written) {
    bits.push(plural(r.written, 'name', 'names') + ' written');
  }
  if (r.failed) bits.push(plural(r.failed, 'was refused', 'were refused'));
  if (r.held) bits.push(plural(r.held, 'is waiting', 'are waiting') + ' for a place that cannot be written yet');
  let text = bits.length ? bits.join(', ') + '.' : (r.dry_run ? 'Nothing to change: ' : 'Nothing changed: ') + 'every device already has one name everywhere.';
  text = text.charAt(0).toUpperCase() + text.slice(1);
  if (r.in_sync && bits.length) text += ' ' + plural(r.in_sync, 'device already matches', 'devices already match') + '.';
  if (broken.length) text += ' Could not read ' + broken.map((s) => s.label).join(', ') + ': ' + broken[0].error;
  const tone = r.failed || broken.length ? 'warn' : (r.written ? 'good' : 'muted');
  return { tone, text };
}

// sourceLine is one place in the report: how many devices it lists and
// whether names can be written there.
export function sourceLine(source) {
  const s = source || {};
  if (s.error) return { tone: 'warn', text: s.label + ': could not be read (' + s.error + ').' };
  if (s.read_only) return { tone: 'warn', text: s.label + ': ' + plural(s.devices || 0, 'device', 'devices') + '. ' + s.read_only + '.' };
  return { tone: 'muted', text: s.label + ': ' + plural(s.devices || 0, 'device', 'devices') + '.' };
}

// headline is the card's status line before anything has been previewed.
export function headline(status) {
  const s = status || {};
  if (!s.available) return { tone: 'muted', text: 'This build cannot sync device names.' };
  if (s.running) return { tone: 'muted', text: 'Syncing names now.' };
  if (s.auto) {
    const last = s.last ? ' Last run: ' + reportSummary(s.last).text : '';
    return { tone: 'good', text: 'Names are kept in sync: a name edited in any one place is written to the others within a couple of minutes.' + last };
  }
  return { tone: 'muted', text: 'Names are not being synced. Check what would change, then sync once or keep them in sync.' };
}

// logLine is one name Shepherd wrote, for the list of recent changes.
export function logLine(entry) {
  const e = entry || {};
  return (e.source || '') + ': ' + (e.old || 'no name') + ' became ' + (e.new || '');
}
