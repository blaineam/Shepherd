// The Watch screen: what Watch mode is doing right now, how much traffic
// is actually moving through Shepherd, which devices are watched and why
// the rest are not, and the kill switch. It polls while visible so the
// throughput numbers are live, and stops the moment the screen is hidden.
//
// Every string that came from the server is placed with textContent.
import { el } from './dom.js';
import { button, emptyState, unavailableCard, confirmDialog, relTime } from './ui.js';
import { unavailable } from './mgmt.js';
import {
  statusHeadline, relayLabel, relayExplanation, ipv6Line, fmtBitsPerSecond, fmtPacketsPerSecond, fmtTotalBytes,
  summarize, sortByTraffic, watchedDevices, historyLine, canKill,
} from './watch.js';

const POLL_MS = 2000;

export function createWatch({ root, mgmt, notify, onOpenDevice = null }) {
  let status = null;
  let loadError = null;
  let timer = 0;
  let busy = false;
  let showAll = false;

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Watch'));
  head.append(title, el('p', 'pg-sub muted', 'Watch mode steers each device’s outbound traffic through Shepherd on its way to your router, so Shepherd sees what a device actually connects to even when it never asks Shepherd to look up a name. It only ever sees the outbound half: what a device sends, not what it downloads. Nothing here blocks anything.'));
  const body = el('div', 'wm-body');
  root.append(head, body);

  const statusCard = el('section', 'card');
  const liveCard = el('section', 'card');
  const devicesCard = el('section', 'card');
  const historyCard = el('section', 'card');

  const cardHead = (t, extra) => {
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', t));
    if (extra) h.append(extra);
    return h;
  };

  const kvRow = (kv) => (k, v, cls = '', titleText = '') => {
    kv.append(el('dt', '', k));
    const dd = el('dd', cls, v);
    if (titleText) dd.title = titleText;
    kv.append(dd);
  };

  function paintStatus() {
    statusCard.replaceChildren(cardHead('Status'));
    const line = statusHeadline(status);
    const headline = el('p', 'wm-headline ' + line.tone, line.text);
    statusCard.append(headline);

    const kv = el('dl', 'nh-kv');
    const row = kvRow(kv);
    if (status.relay) row('Relay', relayLabel(status.relay), '', relayExplanation(status.relay));
    if (status.interface) row('Interface', status.interface, 'mono');
    if (status.gateway_ip) row('Your router', status.gateway_ip + (status.gateway_mac ? ' · ' + status.gateway_mac : ''), 'mono');
    if (status.shepherd_mac) row('Shepherd', (status.shepherd_ips || []).join(' ') + ' · ' + status.shepherd_mac, 'mono');
    if (status.since && status.phase === 'running') row('Running since', relTime(status.since));
    const v6 = ipv6Line(status);
    row('IPv6', v6.text, 'wm-' + v6.tone);
    if (kv.childNodes.length) statusCard.append(kv);

    statusCard.append(el('p', 'muted small wm-note', 'Never watched: your router, Shepherd itself, anything you have excluded, and network equipment such as mesh nodes, access points, smart-home hubs and Thread or Matter devices. Shepherd never sends Router Advertisements, and never steers a smart-home hub, Thread border router or Matter device over IPv6 whatever its own switch says.'));
    statusCard.append(killRow());
  }

  function killRow() {
    const wrap = el('div', 'wm-kill');
    if (!status.enabled) {
      wrap.append(el('p', 'muted small', 'Turn Watch mode on with watch.enabled in shepherd.toml, then restart Shepherd.'));
      return wrap;
    }
    if (!status.armed) {
      const b = button('Re-arm Watch mode', 'primary', () => rearm());
      wrap.append(b, el('p', 'muted small', 'Steering is stopped and stays stopped across restarts until you re-arm it.'));
      return wrap;
    }
    const b = button('Stop all watching', 'danger', () => kill());
    b.disabled = !canKill(status);
    wrap.append(b, el('p', 'muted small', 'Unsteers every device at once and tells each one your router’s real address again. Nothing is watched until you re-arm it, restarts included.'));
    return wrap;
  }

  async function kill() {
    const ok = await confirmDialog({
      title: 'Stop all watching?',
      body: 'Every watched device goes straight back to talking to your router directly. DNS filtering and everything else keeps working. Watch mode stays off, across restarts, until you re-arm it here.',
      confirm: 'Stop watching', danger: true,
    });
    if (!ok) return;
    try {
      status = await mgmt.killWatch();
      paintAll();
      notify('Watch mode stopped. Nothing is being watched.');
    } catch (e) { notify(e.message); }
  }

  async function rearm() {
    try {
      status = await mgmt.rearmWatch();
      paintAll();
      notify('Watch mode re-armed.');
    } catch (e) { notify(e.message); }
  }

  function paintLive() {
    liveCard.replaceChildren(cardHead('Traffic through Shepherd'));
    const st = status.stats || {};
    const tiles = el('div', 'wm-tiles');
    const tile = (label, value, sub) => {
      const t = el('div', 'wm-tile');
      t.append(el('div', 'wm-tile-v', value), el('div', 'wm-tile-k', label));
      if (sub) t.append(el('div', 'wm-tile-s muted', sub));
      tiles.append(t);
    };
    tile('Relayed now', fmtBitsPerSecond(st.bytes_per_second), fmtPacketsPerSecond(st.packets_per_second));
    tile('Relayed in total', fmtTotalBytes(st.bytes_relayed), Number(st.frames_relayed || 0).toLocaleString() + ' packets');
    tile('Devices watched', String(Number(status.steered) || 0), (summarize(status.devices).unhealthy || 0) + ' with no traffic yet');
    liveCard.append(tiles);
    if (Number(st.frames_for_shepherd_itself)) {
      liveCard.append(el('p', 'muted small wm-note', Number(st.frames_for_shepherd_itself).toLocaleString() + ' packets were left alone because a watched device was talking to Shepherd itself (a DNS lookup, this portal) rather than to the internet.'));
    }
    liveCard.append(el('p', 'muted small wm-note', 'This is the outbound direction only, so it is always less than a device’s real traffic: downloads come straight back from your router and never pass through Shepherd.'));
  }

  // One device row. It is a button when the Devices screen can be opened
  // on that device, the same pattern the Vulnerabilities screen uses, so
  // the whole row is the target rather than a link inside it.
  function deviceRow(d, withRate) {
    const clickable = !!(onOpenDevice && d.device_id);
    const row = el(clickable ? 'button' : 'div', 'list-row wm-row');
    if (clickable) {
      row.type = 'button';
      row.setAttribute('aria-label', 'Open ' + (d.name || d.device_id) + ' on the Devices screen');
      row.addEventListener('click', () => onOpenDevice(d.device_id));
    }
    const main = el('div', 'lr-main');
    main.append(el('div', 'lr-name', d.name || d.device_id || 'Unknown device'));
    if (withRate) {
      const parts = [fmtBitsPerSecond(d.bytes_per_second), fmtPacketsPerSecond(d.packets_per_second), fmtTotalBytes(d.bytes_relayed) + ' so far'];
      main.append(el('p', 'lr-desc mono', parts.join('  ·  ')));
      const addrs = (d.steered || []).map((s) => s.ip + ' · ' + s.mac).join('   ');
      if (addrs) main.append(el('p', 'lr-desc mono muted small', addrs));
      if (d.ipv6_reason) main.append(el('p', 'lr-desc muted small', 'IPv4 only: ' + d.ipv6_reason));
    } else if (d.reason) {
      main.append(el('p', 'lr-desc', d.reason));
    }
    const meta = el('div', 'lr-meta');
    if (d.state === 'steered' && !d.healthy) meta.append(el('span', 'badge warn', 'No traffic yet'));
    if (d.state === 'pending') meta.append(el('span', 'badge warn', 'Waiting'));
    if (meta.childNodes.length) main.append(meta);
    row.append(main);
    return row;
  }

  function paintDevices() {
    const sum = summarize(status.devices);
    const toggle = button(showAll ? 'Show only watched' : 'Show every device', 'ghost', () => { showAll = !showAll; paintDevices(); });
    devicesCard.replaceChildren(cardHead('Devices', toggle));
    const counts = [
      sum.steered + ' watched',
      sum.pending ? sum.pending + ' waiting' : '',
      sum.idle ? sum.idle + ' not on the network' : '',
      sum.skipped ? sum.skipped + ' never watched' : '',
      sum.unavailable ? sum.unavailable + ' unavailable' : '',
    ].filter(Boolean).join('  ·  ');
    devicesCard.append(el('p', 'muted small wm-counts', counts));

    const watched = sortByTraffic(watchedDevices(status.devices));
    const list = el('div', 'list-rows');
    if (watched.length) {
      for (const d of watched) list.append(deviceRow(d, true));
    }
    if (showAll) {
      for (const d of status.devices || []) {
        if (d.state !== 'steered') list.append(deviceRow(d, false));
      }
    }
    if (!list.childNodes.length) {
      devicesCard.append(emptyState(status.phase === 'running' ? 'Nothing is being watched yet' : 'Watch mode is not running',
        status.phase === 'running' ? 'Devices are watched as soon as Shepherd has seen them with an address. Open "Show every device" to see why one is not.' : (status.reason || '')));
      return;
    }
    devicesCard.append(list);
  }

  function paintHistory() {
    const recent = [...(status.history || [])].reverse().slice(0, 12);
    historyCard.replaceChildren(cardHead('Recently stopped watching'));
    if (!recent.length) {
      historyCard.append(el('p', 'muted small', 'Nothing has stopped being watched yet.'));
      return;
    }
    historyCard.append(el('p', 'muted small wm-note', 'Shepherd stops watching a device by itself the moment anything looks wrong, and the device goes straight back to its normal path. This is that log.'));
    const list = el('div', 'list-rows');
    for (const rec of recent) {
      const l = historyLine(rec);
      const row = el('div', 'list-row');
      const main = el('div', 'lr-main');
      main.append(el('div', 'lr-name', l.who));
      main.append(el('p', 'lr-desc', l.why));
      main.append(el('p', 'lr-desc muted small', Number.isFinite(l.at) ? relTime(l.at) : ''));
      row.append(main);
      list.append(row);
    }
    historyCard.append(list);
  }

  function paintAll() {
    body.replaceChildren();
    if (loadError) {
      body.append(unavailable(loadError) ? unavailableCard('Watch mode') : emptyState('Could not load Watch mode', loadError.message, button('Try again', 'ghost', load)));
      return;
    }
    if (!status) return;
    body.append(statusCard, liveCard, devicesCard, historyCard);
    paintStatus();
    paintLive();
    paintDevices();
    paintHistory();
  }

  async function load() {
    if (busy) return;
    busy = true;
    try {
      status = await mgmt.watch();
      loadError = null;
    } catch (e) { loadError = e; }
    busy = false;
    paintAll();
  }

  function startPolling() {
    stopPolling();
    timer = setInterval(() => { load().catch(() => {}); }, POLL_MS);
  }

  function stopPolling() {
    if (timer) clearInterval(timer);
    timer = 0;
  }

  return {
    show() { startPolling(); return load(); },
    hide() { stopPolling(); },
  };
}
