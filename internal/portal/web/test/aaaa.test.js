import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AAAA_CHOICES, DEVICE_AAAA_CHOICES, aaaaChoice, deviceAAAAChoice,
  aaaaSwitchOf, aaaaMode, aaaaSummary, aaaaExceptions, exceptionNote,
} from '../js/aaaa.js';

test('every switch has the same three positions the server takes', () => {
  assert.deepEqual(AAAA_CHOICES.map((c) => c.id), ['auto', 'on', 'off']);
  assert.deepEqual(DEVICE_AAAA_CHOICES.map((c) => c.id), ['auto', 'on', 'off']);
  for (const c of [...AAAA_CHOICES, ...DEVICE_AAAA_CHOICES]) {
    assert.ok(c.label && c.text, c.id);
  }
});

test('an unknown value falls back to automatic rather than to a blank control', () => {
  assert.equal(aaaaSwitchOf({ aaaa: 'off' }), 'off');
  assert.equal(aaaaSwitchOf({ aaaa: 'nonsense' }), 'auto');
  assert.equal(aaaaSwitchOf({}), 'auto');
  assert.equal(aaaaSwitchOf(null), 'auto');
  assert.equal(aaaaMode({ mode: 'on' }), 'on');
  assert.equal(aaaaMode({ mode: '' }), 'auto');
  assert.equal(aaaaMode(null), 'auto');
  assert.equal(aaaaChoice('zzz').id, 'auto');
  assert.equal(deviceAAAAChoice('zzz').id, 'auto');
});

test('the summary says what is happening now, and why', () => {
  const auto = aaaaSummary({ mode: 'auto', filtering: true, ipv6_usable: false });
  assert.equal(auto.state, 'filtering');
  assert.match(auto.headline, /withheld/);
  assert.match(auto.detail, /not reachable/);

  const on = aaaaSummary({ mode: 'auto', filtering: false, ipv6_usable: true });
  assert.equal(on.state, 'answering');
  assert.match(on.detail, /is reachable/);

  // A fixed mode says nothing extra: the headline and the switch's own help
  // line already carry it, and repeating it put the sentence on twice.
  const forced = aaaaSummary({ mode: 'on', filtering: true });
  assert.equal(forced.mode, 'on');
  assert.equal(forced.detail, '');

  // Nothing is claimed when the server reported no state at all.
  const none = aaaaSummary({ mode: 'auto' });
  assert.equal(none.state, 'unknown');
  assert.equal(none.detail, '');
});

test('a mode still coming from shepherd.toml says so, because that is the thing to replace', () => {
  const s = aaaaSummary({ mode: 'auto', filtering: true, ipv6_usable: false, from_config: true });
  assert.match(s.detail, /shepherd\.toml/);
  assert.match(s.detail, /not reachable/, 'the automatic reason is still there');
  assert.match(aaaaSummary({ mode: 'off', filtering: false, from_config: true }).detail, /^Set in shepherd\.toml/);
  const saved = aaaaSummary({ mode: 'auto', filtering: true, ipv6_usable: false, from_config: false });
  assert.doesNotMatch(saved.detail, /shepherd\.toml/);
});

test('exceptions put the withheld devices first, then sort by name', () => {
  const doc = {
    exceptions: [
      { id: 'd3', name: 'Printer', aaaa: 'off' },
      { id: 'd1', name: 'Solar Power Monitor', aaaa: 'off' },
      { id: 'd2', name: 'Camera', aaaa: 'on' },
      { id: '', name: 'junk', aaaa: 'on' },
    ],
  };
  assert.deepEqual(aaaaExceptions(doc).map((e) => e.id), ['d2', 'd3', 'd1']);
  assert.deepEqual(aaaaExceptions({}), []);
  assert.deepEqual(aaaaExceptions(null), []);
  assert.match(exceptionNote({ aaaa: 'on' }), /withheld/);
  assert.match(exceptionNote({ aaaa: 'off' }), /in full/);
});
