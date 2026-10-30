// The Locking settings screen: idle auto-lock, PIN setup/change/removal, and
// the trusted-browser list with revoke. Not shown in demo mode (there is no
// real session to manage).
import { el } from './dom.js';
import { button, confirmDialog, relTime, emptyState, unavailableCard } from './ui.js';
import { unavailable } from './mgmt.js';
import { idleChoices, pinIssue } from './locking.js';

export function createLocking({ root, mgmt, notify }) {
  let settings = null; // { idle_lock_minutes, pin_set, trusted_device_count }
  let devices = [];
  let loadError = null;

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  head.append(
    el('h2', 'pg-title', 'Locking'),
    el('p', 'pg-sub muted', 'Shepherd shows synthetic demo data until it is unlocked, and relocks itself after you are idle.')
  );
  const idleCard = el('section', 'card');
  const pinCard = el('section', 'card');
  const devicesCard = el('section', 'card');
  root.append(head, idleCard, pinCard, devicesCard);

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

  function paintPIN() {
    pinCard.replaceChildren(el('h3', 'card-t', 'PIN'));
    if (!settings) return;
    pinCard.append(el('p', 'muted small', settings.pin_set
      ? 'A PIN is set for this portal. It only works together with this browser being trusted.'
      : 'Set a PIN so you do not have to paste the token every time on this browser.'));
    const f = el('form', 'inline-add');
    const inp = el('input');
    inp.type = 'password';
    inp.placeholder = settings.pin_set ? 'New PIN (6-12 chars)' : 'PIN (6-12 chars)';
    inp.autocomplete = 'off';
    inp.setAttribute('aria-label', 'New PIN');
    const save = button(settings.pin_set ? 'Change PIN' : 'Set PIN', 'primary');
    save.type = 'submit';
    const err = el('p', 'err small');
    f.append(inp, save);
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const issue = pinIssue(inp.value);
      if (issue) {
        err.textContent = issue;
        return;
      }
      try {
        await mgmt.setPIN(inp.value);
        inp.value = '';
        notify('PIN saved');
        await load();
      } catch (er) {
        err.textContent = er.message;
      }
    });
    pinCard.append(f, err);
    if (settings.pin_set) {
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
      pinCard.append(off);
    }
  }

  function paintDevices() {
    devicesCard.replaceChildren(el('h3', 'card-t', 'Trusted browsers'));
    if (loadError) {
      devicesCard.append(unavailable(loadError) ? unavailableCard('Trusted browsers') : emptyState('Could not load trusted browsers', loadError.message, button('Try again', 'ghost', load)));
      return;
    }
    if (!devices.length) {
      devicesCard.append(el('p', 'muted small', 'No browser is trusted yet. Set a PIN above to register this one.'));
      return;
    }
    const ul = el('ul', 'list');
    for (const d of devices) {
      const li = el('li');
      const main = el('div');
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
    try {
      const [s, d] = await Promise.all([mgmt.settings(), mgmt.trustedDevices()]);
      settings = (s && s.locking) || settings;
      devices = (d && d.devices) || [];
      loadError = null;
    } catch (e) {
      loadError = e;
    }
    paintIdle();
    paintPIN();
    paintDevices();
  }

  return {
    async show() { await load(); },
    hide() {},
  };
}
