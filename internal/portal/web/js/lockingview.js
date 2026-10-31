// The Locking settings screen: idle auto-lock, PIN setup/change/removal,
// passkeys (add, rename, remove), and the trusted-browser list with revoke.
// Not shown in demo mode (there is no real session to manage).
import { el } from './dom.js';
import { button, confirmDialog, relTime, emptyState, unavailableCard } from './ui.js';
import { unavailable } from './mgmt.js';
import { idleChoices, pinIssue } from './locking.js';
import { creationOptions, registrationJSON, passkeyCardState, ceremonyError } from './passkeys.js';

// webauthn and env are seams for the browser's WebAuthn API and secure-
// context state; the defaults are the real ones.
export function createLocking({
  root, mgmt, notify,
  webauthn = globalThis.navigator && globalThis.navigator.credentials,
  env = () => ({ secureContext: !!globalThis.isSecureContext, hasWebAuthn: !!globalThis.PublicKeyCredential }),
}) {
  let settings = null; // { idle_lock_minutes, pin_set, trusted_device_count }
  let devices = [];
  let loadError = null;
  let passkeyStatus = null; // GET /api/passkeys
  let passkeyError = null;

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  head.append(
    el('h2', 'pg-title', 'Locking'),
    el('p', 'pg-sub muted', 'Shepherd shows synthetic demo data until it is unlocked, and relocks itself after you are idle.')
  );
  const idleCard = el('section', 'card');
  const pinCard = el('section', 'card');
  const passkeyCard = el('section', 'card');
  const devicesCard = el('section', 'card');
  root.append(head, idleCard, pinCard, passkeyCard, devicesCard);

  function paintIdle() {
    idleCard.replaceChildren(el('h3', 'card-t', 'Auto-lock after idle'));
    if (!settings) return;
    const sel = el('select');
    sel.setAttribute('aria-label', 'Auto-lock after idle');
    for (const c of idleChoices(settings.idle_lock_minutes)) {
      const o = el('option', '', c.label);
      o.value = String(c.value);
      if (c.value === settings.idle_lock_minutes) o.selected = true;
      sel.append(o);
    }
    sel.addEventListener('change', async () => {
      const n = Number(sel.value);
      try {
        adoptSettings(await mgmt.setLockingSettings(n));
        notify('Auto-lock saved');
      } catch (e) {
        notify('Could not save: ' + e.message);
        paintIdle();
      }
    });
    idleCard.append(sel, el('p', 'muted small', 'Never keeps you unlocked until you press Lock or sign out. Real activity (not the background status poll) resets the timer.'));
  }

  // paintPIN shows one of three genuinely different cards, since "set a PIN
  // for the first time", "join using the PIN that's already set" and
  // "change the PIN for everyone" are different actions with different
  // consequences, not one overloaded form (see docs/LOCKING.md and the
  // commit history behind this file for why that used to be a trap: typing
  // a fresh "new PIN" from a second browser used to silently change the
  // shared PIN and lock out every already-trusted browser).
  function paintPIN() {
    pinCard.replaceChildren(el('h3', 'card-t', 'PIN'));
    if (!settings) return;
    if (!settings.pin_set) {
      paintSetPIN();
    } else if (!settings.this_device_trusted) {
      paintTrustPIN();
    } else {
      paintChangePIN();
    }
  }

  function paintSetPIN() {
    pinCard.append(el('p', 'muted small', 'Set a PIN so you do not have to paste the token every time on this browser.'));
    pinForm({
      placeholder: 'PIN (6-12 chars)', label: 'New PIN', submitLabel: 'Set PIN',
      checkIssue: pinIssue,
      action: async (pin) => { await mgmt.setPIN(pin); notify('PIN saved'); },
    });
  }

  function paintTrustPIN() {
    pinCard.append(el('p', 'muted small', 'A PIN is already set for this portal, but not on this browser. Enter your existing PIN to trust this browser — this does NOT change the PIN itself.'));
    pinForm({
      placeholder: 'Enter your existing PIN', label: 'Existing PIN', submitLabel: 'Trust this browser',
      action: async (pin) => { await mgmt.trustPIN(pin); notify('This browser is now trusted'); },
    });
    pinCard.append(turnPINOffButton());
  }

  function paintChangePIN() {
    pinCard.append(el('p', 'muted small', 'A PIN is set for this portal and shared by every trusted browser. Changing it stops every OTHER trusted browser from unlocking with the old PIN until you tell them the new one.'));
    pinForm({
      placeholder: 'New PIN (6-12 chars)', label: 'New PIN', submitLabel: 'Change PIN',
      checkIssue: pinIssue,
      confirm: {
        title: 'Change the PIN for every trusted browser?',
        body: 'Every other trusted browser will stop working with the old PIN until you tell them the new one. This browser keeps working with the new PIN.',
        confirm: 'Change PIN', danger: true,
      },
      action: async (pin) => { await mgmt.setPIN(pin); notify('PIN changed'); },
    });
    pinCard.append(turnPINOffButton());
  }

  // pinForm renders one PIN entry form (used by all three cards above) and
  // wires its submit handler: client-side format check (checkIssue, when
  // given), an optional confirmation dialog before anything irreversible,
  // then the actual server call.
  function pinForm({ placeholder, label, submitLabel, checkIssue, confirm, action }) {
    const f = el('form', 'inline-add');
    const inp = el('input');
    inp.type = 'password';
    inp.placeholder = placeholder;
    inp.autocomplete = 'off';
    inp.setAttribute('aria-label', label);
    const save = button(submitLabel, 'primary');
    save.type = 'submit';
    const err = el('p', 'err small');
    f.append(inp, save);
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      if (checkIssue) {
        const issue = checkIssue(inp.value);
        if (issue) {
          err.textContent = issue;
          return;
        }
      }
      if (confirm && !(await confirmDialog(confirm))) return;
      try {
        await action(inp.value);
        inp.value = '';
        await load();
      } catch (er) {
        err.textContent = er.message;
      }
    });
    pinCard.append(f, err);
  }

  function turnPINOffButton() {
    const off = button('Turn PIN off', 'ghost danger');
    off.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'Turn the PIN off?',
        body: 'Every trusted browser will be revoked. You can set a new PIN at any time.',
        confirm: 'Turn off', danger: true,
      });
      if (!ok) return;
      try {
        await mgmt.clearPIN();
        notify('PIN turned off');
        await load();
      } catch (e2) {
        notify('Could not turn off the PIN: ' + e2.message);
      }
    });
    return off;
  }

  // paintPasskeys shows the passkey card. "Add a passkey" is only enabled
  // when a ceremony can actually work from this page (see passkeyCardState):
  // otherwise the card says why - [tls] is off, or this is not the portal's
  // own HTTPS address, with a link there - before anything is attempted.
  function paintPasskeys() {
    passkeyCard.replaceChildren(el('h3', 'card-t', 'Passkeys'));
    if (passkeyError) {
      passkeyCard.append(unavailable(passkeyError) ? unavailableCard('Passkeys') : emptyState('Passkeys are unavailable', passkeyError.message, button('Try again', 'ghost', load)));
      return;
    }
    if (!passkeyStatus) return;
    passkeyCard.append(el('p', 'muted small', 'Unlock with Face ID, Touch ID, Windows Hello, your phone or a security key instead of typing a PIN. The token and PIN keep working either way.'));
    const state = passkeyCardState(passkeyStatus, env());
    if (state.message) {
      const note = el('div', 'note-card');
      const text = el('p', '', state.message);
      note.append(text);
      if (state.goTo) {
        const a = el('a', '', 'Open ' + state.goTo);
        a.href = state.goTo + '/#locking';
        note.append(a);
      }
      passkeyCard.append(note);
    }
    const f = el('form', 'inline-add');
    const name = el('input');
    name.placeholder = 'Name, e.g. My phone';
    name.maxLength = 64;
    name.setAttribute('aria-label', 'Passkey name');
    const add = button('Add a passkey', 'primary');
    add.type = 'submit';
    add.disabled = name.disabled = !state.canAdd;
    const err = el('p', 'err small');
    f.append(name, add);
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      add.disabled = true;
      try {
        const opts = await mgmt.beginPasskeyRegistration(name.value.trim());
        const cred = await webauthn.create({ publicKey: creationOptions(opts) });
        if (!cred) throw new Error('Cancelled.');
        await mgmt.finishPasskeyRegistration(registrationJSON(cred));
        name.value = '';
        notify('Passkey added. Lock and sign in with it once to make sure it works before you rely on it.');
        await load();
      } catch (er) {
        err.textContent = ceremonyError(er);
        add.disabled = false;
      }
    });
    passkeyCard.append(f, err);

    const list = passkeyStatus.passkeys || [];
    if (!list.length) {
      passkeyCard.append(el('p', 'muted small', 'No passkeys yet.'));
      return;
    }
    const ul = el('ul', 'list');
    for (const pk of list) ul.append(passkeyRow(pk));
    passkeyCard.append(ul);
  }

  function passkeyRow(pk) {
    const li = el('li');
    const main = el('div', 'grow');
    const title = el('div', 'small', pk.name);
    const meta = 'Added ' + relTime(pk.created) + ' · ' + (pk.last_used ? 'last used ' + relTime(pk.last_used) : 'never used yet') + (pk.synced ? ' · synced' : '');
    main.append(title, el('div', 'muted small', meta));
    const rename = button('Rename', 'ghost');
    rename.addEventListener('click', () => {
      const f = el('form', 'inline-add');
      const inp = el('input');
      inp.value = pk.name;
      inp.maxLength = 64;
      inp.setAttribute('aria-label', 'New name for ' + pk.name);
      const save = button('Save', 'primary');
      save.type = 'submit';
      const cancel = button('Cancel', 'ghost', () => paintPasskeys());
      f.append(inp, save, cancel);
      f.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
          await mgmt.renamePasskey(pk.id, inp.value.trim());
          notify('Renamed');
          await load();
        } catch (er) {
          notify('Could not rename: ' + er.message);
        }
      });
      title.replaceWith(f);
      rename.hidden = true;
      inp.focus();
    });
    const rm = button('Remove', 'ghost danger');
    rm.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'Remove this passkey?',
        body: pk.name + ' will no longer unlock this portal, and any session it opened ends now. The passkey stays on the device itself; delete it there too if you like.',
        confirm: 'Remove', danger: true,
      });
      if (!ok) return;
      try {
        await mgmt.revokePasskey(pk.id);
        notify('Passkey removed');
        await load();
      } catch (e) {
        notify('Could not remove: ' + e.message);
      }
    });
    li.append(main, rename, rm);
    return li;
  }

  function paintDevices() {
    devicesCard.replaceChildren(el('h3', 'card-t', 'Trusted browsers'));
    if (loadError) {
      devicesCard.append(unavailable(loadError) ? unavailableCard('Trusted browsers') : emptyState('Could not load trusted browsers', loadError.message, button('Try again', 'ghost', load)));
      return;
    }
    if (!devices.length) {
      devicesCard.append(el('p', 'muted small', settings && settings.pin_set
        ? 'No browser is trusted yet. Use the PIN above to trust one.'
        : 'No browser is trusted yet. Set a PIN above to register this one.'));
      return;
    }
    const ul = el('ul', 'list');
    for (const d of devices) {
      const li = el('li');
      const main = el('div', 'grow');
      main.append(
        el('div', 'mono small', d.name || 'Unknown browser'),
        el('div', 'muted small', 'Added ' + relTime(d.created) + ' · last used ' + relTime(d.last_used))
      );
      const rm = button('Revoke', 'ghost danger');
      rm.addEventListener('click', async () => {
        const ok = await confirmDialog({
          title: 'Revoke this browser?',
          body: (d.name || 'This browser') + ' will need the token (or a fresh PIN setup) to unlock again.',
          confirm: 'Revoke', danger: true,
        });
        if (!ok) return;
        try {
          await mgmt.revokeTrustedDevice(d.id);
          notify('Revoked');
          await load();
        } catch (e) {
          notify('Could not revoke: ' + e.message);
        }
      });
      li.append(main, rm);
      ul.append(li);
    }
    devicesCard.append(ul);
  }

  function adoptSettings(s) {
    if (s && s.locking) settings = s.locking;
    paintIdle();
    paintPIN();
  }

  async function load() {
    // Passkeys load on their own, so a passkey problem (say, an unreadable
    // passkeys.json) never hides the PIN or trusted-browser cards.
    const pk = mgmt.passkeys().then((p) => { passkeyStatus = p; passkeyError = null; }, (e) => { passkeyError = e; });
    try {
      const [s, d] = await Promise.all([mgmt.settings(), mgmt.trustedDevices()]);
      settings = (s && s.locking) || settings;
      devices = (d && d.devices) || [];
      loadError = null;
    } catch (e) {
      loadError = e;
    }
    await pk;
    paintIdle();
    paintPIN();
    paintPasskeys();
    paintDevices();
  }

  return {
    async show() { await load(); },
    hide() {},
  };
}
