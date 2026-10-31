import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  b64urlToBytes, bytesToB64url, creationOptions, requestOptions, registrationJSON, assertionJSON,
  browserIssue, passkeyCardState, ceremonyError, staleNote,
} from '../js/passkeys.js';

const bytes = (...a) => new Uint8Array(a);

test('base64url round-trips arbitrary bytes, without padding', () => {
  const all = new Uint8Array(256).map((_, i) => i);
  const s = bytesToB64url(all.buffer);
  assert.doesNotMatch(s, /[+/=]/);
  assert.deepEqual(b64urlToBytes(s), all);
  assert.equal(bytesToB64url(bytes(0xfb, 0xff)), '-_8');
  assert.deepEqual(b64urlToBytes('-_8'), bytes(0xfb, 0xff));
  assert.equal(bytesToB64url(new Uint8Array(0)), '');
  // A typed-array view over part of a buffer encodes only the view.
  const big = bytes(1, 2, 3, 4);
  assert.equal(bytesToB64url(big.subarray(1, 3)), bytesToB64url(bytes(2, 3)));
});

test('creationOptions decodes the binary fields the server sends as base64url', () => {
  // The shape go-webauthn's protocol.CredentialCreation marshals to.
  const server = {
    publicKey: {
      rp: { id: 'shepherd.example.com', name: 'Shepherd' },
      user: { id: 'AAEC', name: 'Shepherd portal', displayName: 'Shepherd portal' },
      challenge: '-_8',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 300000,
      excludeCredentials: [{ type: 'public-key', id: 'AQID', transports: ['internal'] }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      attestation: 'none',
      extensions: { credProps: true },
    },
  };
  const o = creationOptions(server);
  assert.deepEqual(new Uint8Array(o.challenge), bytes(0xfb, 0xff));
  assert.deepEqual(new Uint8Array(o.user.id), bytes(0, 1, 2));
  assert.equal(o.user.name, 'Shepherd portal');
  assert.deepEqual(new Uint8Array(o.excludeCredentials[0].id), bytes(1, 2, 3));
  assert.deepEqual(o.excludeCredentials[0].transports, ['internal']);
  assert.equal(o.rp.id, 'shepherd.example.com');
  assert.equal(o.authenticatorSelection.userVerification, 'required');
  assert.deepEqual(o.extensions, { credProps: true });
  // The server's object is not mutated.
  assert.equal(server.publicKey.challenge, '-_8');
  assert.deepEqual(creationOptions({ publicKey: { ...server.publicKey, excludeCredentials: undefined } }).excludeCredentials, []);
});

test('requestOptions decodes the challenge and allowed credentials', () => {
  const o = requestOptions({ publicKey: { challenge: 'AAEC', rpId: 'shepherd.example.com', userVerification: 'required', allowCredentials: [{ type: 'public-key', id: '-_8' }] } });
  assert.deepEqual(new Uint8Array(o.challenge), bytes(0, 1, 2));
  assert.deepEqual(new Uint8Array(o.allowCredentials[0].id), bytes(0xfb, 0xff));
  assert.equal(o.rpId, 'shepherd.example.com');
  assert.equal(o.userVerification, 'required');
  assert.deepEqual(requestOptions({ publicKey: { challenge: 'AAEC' } }).allowCredentials, []);
});

// A stand-in for the PublicKeyCredential a browser returns.
function fakeCredential(response, extra = {}) {
  return {
    id: 'AQID', rawId: bytes(1, 2, 3).buffer, type: 'public-key', authenticatorAttachment: 'platform',
    response, getClientExtensionResults: () => ({ credProps: { rk: true } }), ...extra,
  };
}

test('registrationJSON produces the body go-webauthn parses', () => {
  const cred = fakeCredential({
    clientDataJSON: bytes(123, 125).buffer, attestationObject: bytes(0xa0).buffer, getTransports: () => ['internal', 'hybrid'],
  });
  assert.deepEqual(registrationJSON(cred), {
    id: 'AQID', rawId: 'AQID', type: 'public-key', authenticatorAttachment: 'platform',
    response: { clientDataJSON: 'e30', attestationObject: 'oA', transports: ['internal', 'hybrid'] },
    clientExtensionResults: { credProps: { rk: true } },
  });
  // Older browsers without getTransports, getClientExtensionResults or an attachment.
  const bare = registrationJSON({ id: 'AQID', rawId: bytes(1, 2, 3).buffer, type: 'public-key', response: { clientDataJSON: bytes(1).buffer, attestationObject: bytes(2).buffer } });
  assert.deepEqual(bare.response.transports, []);
  assert.deepEqual(bare.clientExtensionResults, {});
  assert.equal('authenticatorAttachment' in bare, false);
});

test('assertionJSON carries the signature and user handle', () => {
  const cred = fakeCredential({ clientDataJSON: bytes(1).buffer, authenticatorData: bytes(2).buffer, signature: bytes(3).buffer, userHandle: bytes(4).buffer });
  const j = assertionJSON(cred);
  assert.deepEqual(j.response, { clientDataJSON: 'AQ', authenticatorData: 'Ag', signature: 'Aw', userHandle: 'BA' });
  assert.equal(j.rawId, 'AQID');
  // A null user handle (a non-discoverable credential) is left out.
  const k = assertionJSON(fakeCredential({ clientDataJSON: bytes(1).buffer, authenticatorData: bytes(2).buffer, signature: bytes(3).buffer, userHandle: null }));
  assert.equal('userHandle' in k.response, false);
});

test('browserIssue explains what the browser itself lacks', () => {
  assert.equal(browserIssue({ secureContext: true, hasWebAuthn: true }), '');
  assert.match(browserIssue({ secureContext: true, hasWebAuthn: false }), /does not support passkeys/);
  assert.match(browserIssue({ secureContext: false, hasWebAuthn: true }), /HTTPS/);
});

test('passkeyCardState: refuses early, with the reason, whenever a ceremony could not work', () => {
  const ok = { secureContext: true, hasWebAuthn: true };
  const notConfigured = passkeyCardState({ configured: false, here: false, problem: 'passkeys need ... [tls] ...', passkeys: [], max: 20 }, ok);
  assert.equal(notConfigured.canAdd, false);
  assert.match(notConfigured.message, /\[tls\]/);
  assert.match(notConfigured.message, /^Passkeys need/, 'a server message is capitalized for display');
  assert.equal(notConfigured.goTo, '');

  const elsewhere = passkeyCardState({ configured: true, here: false, problem: 'passkeys only work at https://shepherd.example.com:8443 ...', origin: 'https://shepherd.example.com:8443', passkeys: [], max: 20 }, ok);
  assert.equal(elsewhere.canAdd, false);
  assert.match(elsewhere.message, /only work at/);
  assert.equal(elsewhere.goTo, 'https://shepherd.example.com:8443');

  const noAPI = passkeyCardState({ configured: true, here: true, problem: '', passkeys: [], max: 20 }, { secureContext: true, hasWebAuthn: false });
  assert.equal(noAPI.canAdd, false);
  assert.match(noAPI.message, /does not support/);

  const full = passkeyCardState({ configured: true, here: true, problem: '', passkeys: new Array(20).fill({}), max: 20 }, ok);
  assert.equal(full.canAdd, false);
  assert.match(full.message, /20/);

  const good = passkeyCardState({ configured: true, here: true, problem: '', passkeys: [], max: 20 }, ok);
  assert.deepEqual(good, { canAdd: true, message: '', goTo: '' });
});

test('ceremonyError turns browser exceptions into something a person can act on', () => {
  const dom = (name, message = 'raw') => Object.assign(new Error(message), { name });
  assert.match(ceremonyError(dom('NotAllowedError')), /cancelled|timed out/i);
  assert.match(ceremonyError(dom('InvalidStateError')), /already/);
  assert.match(ceremonyError(dom('SecurityError')), /address/);
  assert.match(ceremonyError(dom('AbortError')), /cancelled/i);
  assert.equal(ceremonyError(dom('Error', 'that passkey was not accepted')), 'That passkey was not accepted');
  assert.equal(ceremonyError(dom('Error', '')), 'Something went wrong.');
  assert.equal(ceremonyError(null), 'Something went wrong.');
});

// fixtures/passkeys.json is real server output (options from the begin
// endpoints) and the bodies a browser posts back, checked on the Go side
// (internal/portal/passkey_fixture_test.go) to parse with go-webauthn. If
// passkeys.js turns the same bytes back into the same JSON, the server can
// read what the browser code sends.
const fixture = JSON.parse(readFileSync(new URL('./fixtures/passkeys.json', import.meta.url), 'utf8'));
const buf = (s) => b64urlToBytes(s).buffer;

test('server creation and request options decode without losing bytes', () => {
  const c = creationOptions(fixture.creation);
  assert.equal(bytesToB64url(c.challenge), fixture.creation.publicKey.challenge);
  assert.equal(bytesToB64url(c.user.id), fixture.creation.publicKey.user.id);
  assert.equal(c.rp.id, 'shepherd.example.com');
  const r = requestOptions(fixture.request);
  assert.equal(bytesToB64url(r.challenge), fixture.request.publicKey.challenge);
  assert.equal(r.allowCredentials.length, 1);
  assert.equal(bytesToB64url(r.allowCredentials[0].id), fixture.request.publicKey.allowCredentials[0].id);
});

test('a browser credential built from the fixture serializes back to the exact body the server accepted', () => {
  const reg = fixture.registration;
  const created = {
    id: reg.id, rawId: buf(reg.rawId), type: reg.type, authenticatorAttachment: reg.authenticatorAttachment,
    response: {
      clientDataJSON: buf(reg.response.clientDataJSON),
      attestationObject: buf(reg.response.attestationObject),
      getTransports: () => reg.response.transports,
    },
    getClientExtensionResults: () => reg.clientExtensionResults,
  };
  assert.deepEqual(registrationJSON(created), reg);

  const as = fixture.assertion;
  const got = {
    id: as.id, rawId: buf(as.rawId), type: as.type, authenticatorAttachment: as.authenticatorAttachment,
    response: {
      clientDataJSON: buf(as.response.clientDataJSON),
      authenticatorData: buf(as.response.authenticatorData),
      signature: buf(as.response.signature),
      userHandle: buf(as.response.userHandle),
    },
    getClientExtensionResults: () => as.clientExtensionResults,
  };
  assert.deepEqual(assertionJSON(got), as);
});

test('staleNote flags a passkey registered for an earlier hostname', () => {
  const status = { configured: true, rp_id: 'new.example.com' };
  assert.equal(staleNote({ rp_id: 'new.example.com' }, status), '');
  assert.match(staleNote({ rp_id: 'old.example.com' }, status), /Registered for old\.example\.com, not new\.example\.com/);
  assert.equal(staleNote({ rp_id: 'old.example.com' }, { configured: false }), '', 'nothing to compare against without [tls]');
  assert.equal(staleNote({}, status), '');
});
