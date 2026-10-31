// Pure helpers for passkey (WebAuthn) unlock, see docs/PASSKEYS.md. The
// server (go-webauthn) sends and expects every binary field as a base64url
// string; navigator.credentials works in ArrayBuffers. These translate
// between the two, and decide - before any ceremony starts - whether one
// can work from this page at all, so a failure is a clear sentence rather
// than a WebAuthn exception in the console.
//
// Nothing here verifies anything: every check that matters (challenge,
// origin, RP ID, signature, user verification, counter) happens on the
// server. These only shuttle bytes and explain refusals.

export function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64url(buf) {
  const u8 = buf instanceof Uint8Array ? buf : ArrayBuffer.isView(buf) ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength) : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const withIDs = (list) => (list || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) }));

// creationOptions turns the server's register/begin answer into the
// publicKey argument for navigator.credentials.create.
export function creationOptions(json) {
  const pk = json.publicKey;
  return {
    ...pk,
    challenge: b64urlToBytes(pk.challenge),
    user: { ...pk.user, id: b64urlToBytes(pk.user.id) },
    excludeCredentials: withIDs(pk.excludeCredentials),
  };
}

// requestOptions turns the server's login/passkey/begin answer into the
// publicKey argument for navigator.credentials.get.
export function requestOptions(json) {
  const pk = json.publicKey;
  return { ...pk, challenge: b64urlToBytes(pk.challenge), allowCredentials: withIDs(pk.allowCredentials) };
}

function common(cred) {
  const out = { id: cred.id, rawId: bytesToB64url(cred.rawId), type: cred.type };
  if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
  return out;
}

const extensionResults = (cred) => (typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {});

// registrationJSON serializes the PublicKeyCredential from create() into
// the body register/finish expects.
export function registrationJSON(cred) {
  const r = cred.response;
  return {
    ...common(cred),
    response: {
      clientDataJSON: bytesToB64url(r.clientDataJSON),
      attestationObject: bytesToB64url(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
    },
    clientExtensionResults: extensionResults(cred),
  };
}

// assertionJSON serializes the PublicKeyCredential from get() into the
// body login/passkey/finish expects.
export function assertionJSON(cred) {
  const r = cred.response;
  const response = {
    clientDataJSON: bytesToB64url(r.clientDataJSON),
    authenticatorData: bytesToB64url(r.authenticatorData),
    signature: bytesToB64url(r.signature),
  };
  if (r.userHandle) response.userHandle = bytesToB64url(r.userHandle);
  return { ...common(cred), response, clientExtensionResults: extensionResults(cred) };
}

// browserIssue reports what this browser lacks, or ''. env is
// { secureContext: window.isSecureContext, hasWebAuthn: !!window.PublicKeyCredential }.
export function browserIssue(env) {
  if (!env.hasWebAuthn) return 'This browser does not support passkeys.';
  if (!env.secureContext) return 'Passkeys need a secure (HTTPS) page.';
  return '';
}

// passkeyCardState decides what the Locking screen's passkey card offers,
// from GET /api/passkeys and the browser environment: whether "Add a
// passkey" is enabled, the reason when it is not, and where to go instead
// (the portal's own HTTPS address) when that is the fix.
export function passkeyCardState(status, env) {
  if (!status.configured) return { canAdd: false, message: sentence(status.problem), goTo: '' };
  if (!status.here) return { canAdd: false, message: sentence(status.problem), goTo: status.origin || '' };
  const issue = browserIssue(env);
  if (issue) return { canAdd: false, message: issue, goTo: '' };
  if ((status.passkeys || []).length >= status.max) {
    return { canAdd: false, message: `At most ${status.max} passkeys can be registered. Remove one to add another.`, goTo: '' };
  }
  return { canAdd: true, message: '', goTo: '' };
}

// staleNote explains a passkey that was registered for a different
// hostname than the current relying party (the [tls] hostname changed): it
// can never sign in again and is listed only so it can be removed. ''
// for a passkey that is fine, or when passkeys are not configured at all.
export function staleNote(pk, status) {
  if (!status.configured || !pk.rp_id || pk.rp_id === status.rp_id) return '';
  return `Registered for ${pk.rp_id}, not ${status.rp_id}: it cannot sign in here any more. Remove it and add a new one.`;
}

// sentence capitalizes a server message (Go error strings start lowercase)
// for display on its own.
function sentence(s) {
  return s ? s[0].toUpperCase() + s.slice(1) : '';
}

// ceremonyError explains a failed create()/get() or a server refusal.
export function ceremonyError(err) {
  if (!err) return 'Something went wrong.';
  switch (err.name) {
    case 'NotAllowedError': return 'Cancelled, or the passkey prompt timed out.';
    case 'AbortError': return 'Cancelled.';
    case 'InvalidStateError': return 'This authenticator already has a passkey for this portal.';
    case 'SecurityError': return "The browser refused: this page's address does not match the passkey's.";
    default: return sentence(err.message) || 'Something went wrong.';
  }
}
