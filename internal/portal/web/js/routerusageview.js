// The "read bandwidth from your router" section of the Bandwidth screen.
// Watch mode measures by steering traffic through Shepherd; this is the
// passive alternative for a network that will not tolerate that.
//
// Routers and firewalls are connected on the Router screen, where all of
// them sit side by side (connectionsview.js). This section only says what
// the reader is doing and points there.
//
// Every string that came from the server is placed with textContent.
import { el } from './dom.js';
import { button } from './ui.js';
import { routerConnection } from './traffic.js';

export function createRouterUsage({ onManage = null }) {
  const root = el('section', 'card ru');
  let router = null;

  function paint() {
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', 'Read from your router'));
    root.replaceChildren(h);
    const line = routerConnection(router);
    const p = el('p', 'ru-line ' + line.tone, line.text);
    p.setAttribute('role', 'status');
    root.append(p);
    if (!router || !router.available) return;
    root.append(el('p', 'muted small ru-note',
      'Shepherd asks your router or firewall what each device has moved. Nothing is put in the path of your traffic, so this works where Watch mode cannot.'));
    if (onManage) {
      const acts = el('div', 'ru-acts');
      acts.append(button(router.connected ? 'Manage connections' : 'Connect a router', router.connected ? 'ghost' : 'primary', onManage));
      root.append(acts, el('p', 'muted small ru-note', 'Routers and firewalls are connected on the Router screen.'));
    }
  }

  paint();
  return {
    root,
    // render is called with the router object from GET /api/traffic on
    // every poll, so the status line stays live without its own timer.
    render(next) {
      router = next;
      paint();
    },
  };
}
