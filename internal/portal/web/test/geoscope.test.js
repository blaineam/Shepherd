import test from 'node:test';
import assert from 'node:assert/strict';
import { NETWORK } from '../js/scope.js';
import { normalizeGeoBlock, listFor, countryStatus, setCountry, effectiveCountries } from '../js/geoscope.js';

const kids = { kind: 'group', id: 'kids' };
const tv = { kind: 'device', id: 'tv-1' };

test('normalizeGeoBlock tolerates junk and missing fields', () => {
  assert.deepEqual(normalizeGeoBlock(null), { network: [], groups: {}, devices: {} });
  assert.deepEqual(normalizeGeoBlock({ network: 'nope', groups: 1 }), { network: [], groups: {}, devices: {} });
  assert.deepEqual(normalizeGeoBlock({ network: ['FR'], groups: { kids: ['KP'] } }), { network: ['FR'], groups: { kids: ['KP'] }, devices: {} });
});

test('listFor reads each scope kind, defaulting to empty', () => {
  const gb = { network: ['FR'], groups: { kids: ['KP'] }, devices: {} };
  assert.deepEqual(listFor(gb, NETWORK), ['FR']);
  assert.deepEqual(listFor(gb, kids), ['KP']);
  assert.deepEqual(listFor(gb, tv), []);
});

test('countryStatus: here, inherited and effective', () => {
  const gb = { network: ['FR'], groups: { kids: ['KP'] }, devices: { 'tv-1': ['IR'] } };
  const st = countryStatus(gb, tv, ['kids'], 'FR');
  assert.equal(st.here, false);
  assert.equal(st.inherited.length, 1); // from network
  assert.equal(st.effective, true);

  const st2 = countryStatus(gb, tv, ['kids'], 'IR');
  assert.equal(st2.here, true);
  assert.deepEqual(st2.inherited, []);

  const st3 = countryStatus(gb, NETWORK, [], 'KP');
  assert.equal(st3.here, false);
  assert.equal(st3.inherited.length, 0); // network has nothing broader than it
  assert.equal(st3.effective, false);
});

test('setCountry adds and removes without mutating the input', () => {
  const gb = normalizeGeoBlock({ network: ['FR'] });
  const added = setCountry(gb, NETWORK, 'DE', true);
  assert.deepEqual(added.network, ['FR', 'DE']);
  assert.deepEqual(gb.network, ['FR']); // original untouched

  const already = setCountry(added, NETWORK, 'DE', true);
  assert.deepEqual(already.network, ['FR', 'DE']); // no duplicate

  const removed = setCountry(added, NETWORK, 'FR', false);
  assert.deepEqual(removed.network, ['DE']);

  const g1 = setCountry(gb, kids, 'KP', true);
  assert.deepEqual(g1.groups, { kids: ['KP'] });
  const d1 = setCountry(g1, tv, 'IR', true);
  assert.deepEqual(d1.devices, { 'tv-1': ['IR'] });
});

test('effectiveCountries unions the whole chain', () => {
  const gb = { network: ['FR'], groups: { kids: ['KP'] }, devices: { 'tv-1': ['IR'] } };
  const set = effectiveCountries(gb, tv, ['kids']);
  assert.deepEqual([...set].sort(), ['FR', 'IR', 'KP']);
  assert.deepEqual([...effectiveCountries(gb, NETWORK, [])], ['FR']);
});
