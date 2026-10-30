// Remembers client address -> friendly device name from entries seen, so
// places that only know an address (top devices, filters) can show names.
export function createNameBook() {
  const map = new Map();
  const wander = new Set();
  return {
    note(e) {
      if (!e || !e.client) return;
      if (e.device && e.device !== e.client) map.set(e.client, e.device);
      if (e.wandering) wander.add(e.client); else wander.delete(e.client);
    },
    isWandering(ip) { return wander.has(ip); },
    label(ip) { return map.get(ip) || ip; },
    has(ip) { return map.has(ip); },
    get size() { return map.size; },
  };
}
