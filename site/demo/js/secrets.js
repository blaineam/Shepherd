// Wording and form checks for the two portal-managed secrets: the DNS
// provider token (Proxy tab) and the accountability mail relay
// (Accountability tab). Pure. The server validates and checks everything
// again (internal/secrets, api_secrets.go); this explains a mistake while
// typing instead of after a round trip. Secrets are write-only: nothing
// here ever expects a token or password to come back from the server.

export const TLS_MODES = [
  ['starttls', 'STARTTLS (usually port 587)'],
  ['tls', 'TLS from the start (usually port 465)'],
  ['none', 'No encryption (only a relay on this machine or LAN)'],
];

const DEFAULT_PORT = { starttls: 587, tls: 465, none: 25 };

// The port to suggest when the TLS mode changes: only replace a port that
// is one of the defaults (or empty), never one the owner typed.
export function portForMode(mode, currentPort) {
  const cur = Number(currentPort);
  const isDefault = !currentPort || Object.values(DEFAULT_PORT).includes(cur);
  return isDefault ? DEFAULT_PORT[mode] || cur : cur;
}

const FEATURE = { tls: 'the portal\'s own HTTPS ([tls])', reverseproxy: 'the reverse proxy\'s wildcard certificate' };

function day(iso) {
  const t = Date.parse(iso || '');
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : '';
}

// "Imported from shepherd.toml on 2026-10-30" / "Saved in the portal on …".
export function sourceText(doc) {
  if (!doc || !doc.source) return '';
  const when = day(doc.updated_at);
  const suffix = when ? ' on ' + when : '';
  if (!doc.configured) return 'Removed in the portal' + suffix;
  if (doc.source === 'shepherd.toml') return 'Imported from shepherd.toml' + suffix + '; edit it here from now on';
  return 'Saved in the portal' + suffix;
}

// Which features use the token, as a sentence.
export function usedByText(usedBy) {
  const names = (usedBy || []).map((u) => FEATURE[u] || u);
  if (!names.length) return 'Nothing uses it yet: certificates are only requested once [reverseproxy] or [tls] is enabled in shepherd.toml.';
  return 'Used for ' + names.join(' and ') + '.';
}

// One line about the DNS provider token, with a tone for its color.
export function dnsProviderSummary(doc) {
  if (!doc) return { tone: 'muted', text: 'Unknown' };
  if (doc.configured) return { tone: 'good', text: 'Token set' };
  if ((doc.used_by || []).length) return { tone: 'warn', text: 'No token: certificates cannot be issued until one is set' };
  return { tone: 'muted', text: 'No token set' };
}

// Builds the PUT /api/dns-provider body, or says what is wrong.
export function tokenBody(input, provider = 'cloudflare') {
  const t = String(input || '').trim();
  if (!t) return { ok: false, error: 'Paste the API token' };
  if (/\s/.test(t)) return { ok: false, error: 'A token has no spaces in it; check what was pasted' };
  if (t.length > 2048) return { ok: false, error: 'That is far longer than any API token' };
  return { ok: true, body: { provider, api_token: t } };
}

// One line about the mail relay, with a tone for its color.
export function relayStatus(doc) {
  if (!doc) return { tone: 'muted', text: 'Unknown' };
  if (!doc.enabled) return { tone: 'muted', text: 'Accountability is turned off in shepherd.toml ([accountability] enabled = false); a relay saved here is kept for when it is on' };
  if (!doc.configured) return { tone: 'warn', text: 'No mail relay yet: nothing is emailed until one is set below' };
  const mode = { starttls: 'STARTTLS', tls: 'TLS', none: 'unencrypted' }[doc.tls] || doc.tls;
  return { tone: 'good', text: 'Sending through ' + doc.host + ':' + doc.port + ' (' + mode + ')' };
}

const HOST = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;

// Builds the PUT /api/accountability/smtp body from the form, or says
// which field is wrong. current is the last GET answer: a blank password
// keeps the saved one, but only for the same host and username (the server
// enforces this too, so a saved password is never sent to a new server).
export function relayBody(form, current) {
  const host = String(form.host || '').trim();
  const username = String(form.username || '').trim();
  const from = String(form.from || '').trim();
  const password = String(form.password || '');
  const tls = form.tls || 'starttls';
  if (!host) return { ok: false, field: 'host', error: 'Enter the relay\'s host name, like smtp.example.com' };
  if (/[\s/:@]/.test(host) || !HOST.test(host)) return { ok: false, field: 'host', error: 'Just the host name: no scheme, port or path' };
  const port = Number(String(form.port ?? '').trim());
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, field: 'port', error: 'The port is a number from 1 to 65535' };
  if (!TLS_MODES.some(([m]) => m === tls)) return { ok: false, field: 'tls', error: 'Choose how to secure the connection' };
  if (/\s/.test(username)) return { ok: false, field: 'username', error: 'The username has no spaces' };
  if (!from || !/^[^\s@]+@[^\s@]+$/.test(from)) return { ok: false, field: 'from', error: 'Enter the address mail is sent from, like shepherd@example.com' };
  if (/[\r\n]/.test(password)) return { ok: false, field: 'password', error: 'The password cannot contain a line break' };
  const body = { host, port, username, from, tls };
  if (form.clearPassword) {
    body.clear_password = true;
  } else if (password) {
    body.password = password;
  } else if (current && current.password_set && username && (current.host !== host || current.username !== username)) {
    return { ok: false, field: 'password', error: 'Enter the password again: the host or username changed, and a saved password is only ever sent to the server it was entered for' };
  }
  return { ok: true, body };
}

// The password field's placeholder, which is the only hint that a saved
// password exists (its value never comes back).
export function passwordPlaceholder(current) {
  return current && current.password_set ? 'Saved; leave blank to keep it' : 'Password or app password';
}
