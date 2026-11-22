// Pure helpers for the Device names card on the Router screen
// (namesyncview.js): one name per device across Shepherd and everything
// connected. Nothing here touches the DOM.

const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

// The same engine syncs two things, and the screen has to say each in its
// own words. WORDS holds them: 'names' for device names, 'groups' for which
// group a device is in. Every helper below takes the kind last and reads
// names when it is left out.
export const WORDS = {
  names: {
    none: 'no name',
    unit: ['name', 'names'],
    would: 'would be written', did: 'written',
    settled: 'every device already has one name everywhere.',
    first: (from) => 'the most readable name, from ' + from,
    edit: (from) => 'renamed on ' + from,
    catchup: 'catching up with the agreed name',
    cannot: 'This build cannot sync device names.',
    running: 'Syncing names now.',
    on: 'Names are kept in sync: a name edited in any one place is written to the others within a couple of minutes.',
    off: 'Names are not being synced. Check what would change, then sync once or keep them in sync.',
    log: (e) => (e.old || 'no name') + ' became ' + (e.new || ''),
  },
  groups: {
    none: 'no group',
    unit: ['device', 'devices'],
    would: 'would be moved', did: 'moved',
    settled: 'every device is already in the same group everywhere.',
    first: (from) => 'its group in ' + from,
    edit: (from) => 'moved on ' + from,
    catchup: 'catching up with the agreed group',
    cannot: 'This build cannot sync device groups.',
    running: 'Syncing groups now.',
    on: 'Groups are kept in sync: a device moved in one place is moved in the other within a couple of minutes.',
    off: 'Groups are not being synced. Check what would change, then sync once or keep them in sync.',
    log: (e) => 'moved from ' + (e.old || 'no group') + ' to ' + (e.new || 'no group'),
  },
};
const words = (kind) => WORDS[kind] || WORDS.names;

// labelOf writes a source id the way the screen does.
export function labelOf(report, id) {
  const s = ((report || {}).sources || []).find((x) => x.id === id);
  return s ? s.label : id;
}


// changeLine is one device's change as a row: the name it gets, why, what
// it is called now in each place, and where the name goes.
export function changeLine(change, report, kind) {
  const c = change || {};
  const w = words(kind);
  const lab = (id) => labelOf(report, id);
  const why = c.reason === 'catchup' ? w.catchup : (typeof w[c.reason] === 'function' ? w[c.reason](lab(c.from)) : '');
  const was = Object.entries(c.names || {})
    .filter(([, name]) => name !== c.name)
    .map(([id, name]) => lab(id) + ': ' + (name || w.none));
  const failed = Object.entries(c.failed || {}).map(([id, msg]) => lab(id) + ' refused it: ' + msg);
  return {
    // A group sync can settle on "no group", which still needs a label.
    name: c.name || (kind === 'groups' && change ? w.none : ''),
    why,
    was: was.join(' · '),
    to: (c.writes || []).map(lab).join(', '),
    held: (c.held || []).map(lab).join(', '),
    failed: failed.join(' · '),
  };
}

// reportSummary is a preview or a finished run in one sentence, with a tone.
export function reportSummary(report, kind) {
  const r = report || {};
  const w = words(kind);
  const broken = (r.sources || []).filter((s) => s.error);
  const bits = [];
  if (r.dry_run) {
    if (r.written) bits.push(plural(r.written, ...w.unit) + ' ' + w.would);
  } else if (r.written) {
    bits.push(plural(r.written, ...w.unit) + ' ' + w.did);
  }
  if (r.failed) bits.push(plural(r.failed, 'was refused', 'were refused'));
  if (r.held) bits.push(plural(r.held, 'is waiting', 'are waiting') + ' for a place that cannot be written yet');
  let text = bits.length ? bits.join(', ') + '.' : (r.dry_run ? 'Nothing to change: ' : 'Nothing changed: ') + w.settled;
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
export function headline(status, kind) {
  const s = status || {};
  const w = words(kind);
  if (!s.available) return { tone: 'muted', text: w.cannot };
  if (s.running) return { tone: 'muted', text: w.running };
  if (s.auto) {
    const last = s.last ? ' Last run: ' + reportSummary(s.last, kind).text : '';
    return { tone: 'good', text: w.on + last };
  }
  return { tone: 'muted', text: w.off };
}

// logLine is one name Shepherd wrote, for the list of recent changes.
export function logLine(entry, kind) {
  const e = entry || {};
  return (e.source || '') + ': ' + words(kind).log(e);
}
