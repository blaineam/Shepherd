// Idle locking counts only calls that mean a person is there, and polling
// does not (see the server's authPassive). Looking at the map, panning the
// globe or scrolling a list makes no such call, so a portal in active use
// relocked after the idle window anyway. This reports real input to the
// server, at most once per interval, so the window slides while someone is
// using the page and still expires on a tab left open.
export const ACTIVITY_INTERVAL_MS = 60 * 1000;
export const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart', 'pointermove'];

export function startActivityReports({ target, send, now = () => Date.now(), interval = ACTIVITY_INTERVAL_MS }) {
  let last = -Infinity;
  const onInput = () => {
    const t = now();
    if (t - last < interval) return;
    last = t;
    Promise.resolve(send()).catch(() => {});
  };
  for (const ev of ACTIVITY_EVENTS) target.addEventListener(ev, onInput, { passive: true, capture: true });
  return () => { for (const ev of ACTIVITY_EVENTS) target.removeEventListener(ev, onInput, { capture: true }); };
}
