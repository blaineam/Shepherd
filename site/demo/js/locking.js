// Pure helpers for portal locking: the demo/locked URL dance the frontend
// uses to switch modes (see app.js), and a client-side mirror of the
// server's PIN strength check for instant feedback before the request.

// lockedURL adds ?demo=1&locked=1 to href, so a reload boots straight into
// demo mode with the lock banner showing. This reuses the same "reload to
// switch modes" trick the manual demo toggle already uses, rather than
// rewiring the DEMO constant everywhere it is read at module load.
export function lockedURL(href) {
  const u = new URL(href);
  u.searchParams.set('demo', '1');
  u.searchParams.set('locked', '1');
  return u.toString();
}

// unlockedURL strips every demo/locked marker, so a reload boots into the
// real, authenticated view.
export function unlockedURL(href) {
  const u = new URL(href);
  for (const k of ['demo', 'locked', 'rate', 'bytes', 'setup_pin']) u.searchParams.delete(k);
  return u.toString();
}

export function isLockedDemo(href) {
  return new URL(href).searchParams.get('locked') === '1';
}

// pinIssue mirrors validatePIN/weakPIN in internal/portal/locking_store.go:
// 6-12 letters/digits, not all one character, not a simple run. It is only
// for instant feedback; the server is always the real check.
export function pinIssue(pin) {
  if (pin.length < 6 || pin.length > 12) return 'PIN must be 6 to 12 characters';
  if (!/^[A-Za-z0-9]+$/.test(pin)) return 'PIN must be letters and digits only';
  if (weakPIN(pin)) return 'Choose a less predictable PIN';
  return '';
}

function weakPIN(pin) {
  if ([...pin].every((c) => c === pin[0])) return true;
  if (/^[0-9]+$/.test(pin)) {
    let asc = true;
    let desc = true;
    for (let i = 1; i < pin.length; i++) {
      if (pin.charCodeAt(i) !== pin.charCodeAt(i - 1) + 1) asc = false;
      if (pin.charCodeAt(i) !== pin.charCodeAt(i - 1) - 1) desc = false;
    }
    if (asc || desc) return true;
  }
  return false;
}

// idleChoices renders the settings dropdown: fixed stops plus the current
// value if it is not one of them, so a custom saved value is never silently
// dropped from its own selector.
export const IDLE_STOPS = [0, 5, 10, 30, 60];

export function idleChoices(current) {
  const stops = IDLE_STOPS.includes(current) ? IDLE_STOPS : [...IDLE_STOPS, current].sort((a, b) => a - b);
  return stops.map((n) => ({ value: n, label: n === 0 ? 'Never' : n + ' minutes' }));
}

// ---------------------------------------------------------- sign-in order
//
// The lock screen leads with one way in rather than showing three at once.
// The order is passkey, then PIN, then the token (docs/LOCKING.md): the
// passkey is the one with nothing to type, the PIN is the short thing you
// remember, and the token is the long one you keep in a password manager
// and need when the other two are gone.
//
// "Available" is what the server said plus what this browser can actually
// do: a passkey is no use without WebAuthn and a secure context, however
// many are registered. The token is always last and always reachable,
// because it is the way back in when a phone is lost or a PIN forgotten --
// collapsing it is fine, hiding it would not be.

export const SIGNIN_METHODS = ['passkey', 'pin', 'token'];

// signInOrder returns the methods to offer, best first. methods is the
// server's answer ({passkey, pin}); browser says what this browser can do.
export function signInOrder(methods, browser = {}) {
  const m = methods || {};
  const can = {
    passkey: !!m.passkey && browser.hasWebAuthn !== false && browser.secureContext !== false,
    pin: !!m.pin,
    token: true,
  };
  return SIGNIN_METHODS.filter((name) => can[name]);
}

// autoTryPasskey reports whether to start the passkey ceremony without
// waiting to be asked. Only when a passkey is the best way in, only on a
// page the owner is actually looking at (a prompt on a background tab is
// an interruption nobody asked for), and only once per page: a failed or
// cancelled attempt leaves the button, rather than prompting again in a
// loop the owner cannot get out of.
export function autoTryPasskey({ order = [], visible = true, tried = false } = {}) {
  return order[0] === 'passkey' && visible && !tried;
}

// methodLabel is what the collapsed alternatives are called, phrased as
// the thing the owner would go looking for.
export function methodLabel(name) {
  switch (name) {
    case 'passkey': return 'Use a passkey';
    case 'pin': return 'Use your PIN';
    default: return 'Use the portal token';
  }
}
