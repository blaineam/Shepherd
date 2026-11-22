import { test } from 'node:test';
import assert from 'node:assert/strict';
import { labelOf, changeLine, reportSummary, sourceLine, headline, logLine } from '../js/namesync.js';

const sources = [
  { id: 'shepherd', label: 'Shepherd', devices: 80 },
  { id: 'eero', label: 'eero', devices: 78 },
  { id: 'firewalla', label: 'Firewalla', devices: 80, read_only: 'Allow changes is off for your Firewalla' },
];

test('a source is written by its label, or its id when the report does not list it', () => {
  assert.equal(labelOf({ sources }, 'firewalla'), 'Firewalla');
  assert.equal(labelOf({ sources }, 'unifi'), 'unifi');
  assert.equal(labelOf(null, 'eero'), 'eero');
});

test('a change says the name, why it won, what it replaces and where it goes', () => {
  const line = changeLine({
    mac: '02005e000001', name: 'Kitchen speaker', reason: 'first', from: 'eero',
    names: { shepherd: 'ESP_4F21C0', eero: 'Kitchen speaker', firewalla: '' },
    writes: ['shepherd'], held: ['firewalla'],
  }, { sources });
  assert.equal(line.name, 'Kitchen speaker');
  assert.equal(line.why, 'the most readable name, from eero');
  assert.equal(line.was, 'Shepherd: ESP_4F21C0 · Firewalla: no name');
  assert.equal(line.to, 'Shepherd');
  assert.equal(line.held, 'Firewalla');
  assert.equal(line.failed, '');

  assert.equal(changeLine({ name: 'Den TV', reason: 'edit', from: 'firewalla', names: {} }, { sources }).why, 'renamed on Firewalla');
  assert.equal(changeLine({ name: 'Den TV', reason: 'catchup', names: {} }, { sources }).why, 'catching up with the agreed name');
  assert.equal(changeLine({ name: 'Den TV', reason: 'new', names: {} }, { sources }).why, '');
  assert.equal(changeLine({ name: 'Den TV', failed: { eero: 'HTTP 500' } }, { sources }).failed, 'eero refused it: HTTP 500');
  assert.deepEqual(changeLine(null, null), { name: '', why: '', was: '', to: '', held: '', failed: '' });
});

test('a report is one sentence, worded for a preview or a finished run', () => {
  assert.deepEqual(reportSummary({ dry_run: true, written: 3, in_sync: 40, sources }), { tone: 'good', text: '3 names would be written. 40 devices already match.' });
  assert.equal(reportSummary({ dry_run: true, written: 1, in_sync: 1 }).text, '1 name would be written. 1 device already matches.');
  assert.equal(reportSummary({ written: 2 }).text, '2 names written.');
  assert.deepEqual(reportSummary({ dry_run: true }), { tone: 'muted', text: 'Nothing to change: every device already has one name everywhere.' });
  assert.equal(reportSummary({}).text, 'Nothing changed: every device already has one name everywhere.');
  assert.equal(reportSummary(null).tone, 'muted');

  const held = reportSummary({ dry_run: true, written: 0, held: 2 });
  assert.equal(held.text, '2 are waiting for a place that cannot be written yet.');
  assert.equal(reportSummary({ held: 1 }).text, '1 is waiting for a place that cannot be written yet.');

  const failed = reportSummary({ written: 1, failed: 2 });
  assert.equal(failed.tone, 'warn');
  assert.equal(failed.text, '1 name written, 2 were refused.');
  assert.match(reportSummary({ failed: 1 }).text, /^1 was refused\.$/);

  const broken = reportSummary({ dry_run: true, written: 1, sources: [{ id: 'eero', label: 'eero', error: 'the session has expired' }] });
  assert.equal(broken.tone, 'warn');
  assert.match(broken.text, /Could not read eero: the session has expired/);
});

test('each place says how many devices it lists and whether it can be written', () => {
  assert.deepEqual(sourceLine(sources[0]), { tone: 'muted', text: 'Shepherd: 80 devices.' });
  assert.equal(sourceLine({ label: 'eero', devices: 1 }).text, 'eero: 1 device.');
  const ro = sourceLine(sources[2]);
  assert.equal(ro.tone, 'warn');
  assert.equal(ro.text, 'Firewalla: 80 devices. Allow changes is off for your Firewalla.');
  assert.equal(sourceLine({ label: 'eero', error: 'timeout' }).text, 'eero: could not be read (timeout).');
  assert.equal(sourceLine({ label: 'eero' }).text, 'eero: 0 devices.');
});

test('the headline says whether names are being kept in sync', () => {
  assert.match(headline(null).text, /cannot sync device names/);
  assert.equal(headline({ available: true, running: true, auto: true }).text, 'Syncing names now.');
  assert.match(headline({ available: true }).text, /not being synced/);
  const on = headline({ available: true, auto: true });
  assert.equal(on.tone, 'good');
  assert.match(on.text, /within a couple of minutes\.$/);
  assert.match(headline({ available: true, auto: true, last: { written: 2 } }).text, /Last run: 2 names written\.$/);
});

test('a log entry reads as what became what, and where', () => {
  assert.equal(logLine({ source: 'eero', old: 'ESP_4F21C0', new: 'Kitchen speaker' }), 'eero: ESP_4F21C0 became Kitchen speaker');
  assert.equal(logLine({ source: 'firewalla', old: '', new: 'Den TV' }), 'firewalla: no name became Den TV');
  assert.equal(logLine(null), ': no name became ');
});

test('the same helpers word a group sync in its own terms', () => {
  const report = { sources };
  const line = changeLine({ name: 'Smart Home', reason: 'first', from: 'shepherd', names: { shepherd: 'Smart Home', firewalla: '' }, writes: ['firewalla'] }, report, 'groups');
  assert.equal(line.why, 'its group in Shepherd');
  assert.equal(line.was, 'Firewalla: no group');
  assert.equal(changeLine({ name: '', reason: 'edit', from: 'firewalla', names: { shepherd: 'Den' } }, report, 'groups').name, 'no group');
  assert.equal(changeLine({ name: '', reason: 'edit', from: 'firewalla', names: {} }, report, 'groups').why, 'moved on Firewalla');
  assert.equal(changeLine({ name: 'Den', reason: 'catchup', names: {} }, report, 'groups').why, 'catching up with the agreed group');
  assert.equal(changeLine(null, null, 'groups').name, '');

  assert.equal(reportSummary({ dry_run: true, written: 3, in_sync: 40 }, 'groups').text, '3 devices would be moved. 40 devices already match.');
  assert.equal(reportSummary({ written: 1 }, 'groups').text, '1 device moved.');
  assert.equal(reportSummary({ dry_run: true }, 'groups').text, 'Nothing to change: every device is already in the same group everywhere.');

  assert.match(headline(null, 'groups').text, /cannot sync device groups/);
  assert.equal(headline({ available: true, running: true }, 'groups').text, 'Syncing groups now.');
  assert.match(headline({ available: true }, 'groups').text, /Groups are not being synced/);
  assert.match(headline({ available: true, auto: true, last: { written: 2 } }, 'groups').text, /moved in the other within a couple of minutes\. Last run: 2 devices moved\.$/);

  assert.equal(logLine({ source: 'firewalla', old: '', new: 'Smart Home' }, 'groups'), 'firewalla: moved from no group to Smart Home');
  assert.equal(logLine({ source: 'shepherd', old: 'Den', new: '' }, 'groups'), 'shepherd: moved from Den to no group');
  // An unknown kind reads as names rather than failing.
  assert.equal(logLine({ source: 'eero', old: 'a', new: 'b' }, 'colours'), 'eero: a became b');
});
