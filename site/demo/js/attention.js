// Pure helpers for the Devices screen's "Needs attention" panel: devices
// that are brand new/quarantined, wandering, or excluded are easy to miss
// mixed alphabetically or by recency into a list of 91 otherwise-identical
// rows (see docs/DEVICES.md's Quarantine/Excluded/Wandering sections - these
// are exactly the states worth a glance before anything else). No DOM, no
// network, so the merge/priority logic is unit-testable on its own, the
// same split every other *view.js file in this directory follows.

// REASON_PRIORITY orders which state leads when a device matches more than
// one: a brand-new, never-reviewed device is the most urgent thing to look
// at, ahead of a device someone already deliberately excluded or set
// wandering.
const REASON_PRIORITY = { quarantine: 0, wandering: 1, excluded: 2 };

export function attentionReasonLabel(reason) {
  switch (reason) {
    case 'quarantine': return 'New / quarantined';
    case 'wandering': return 'Wandering';
    case 'excluded': return 'Excluded';
    default: return reason || '';
  }
}

// mergeAttention takes [{reason, devices}] (one GET /api/devices result per
// reason, e.g. wandering:true, excluded:true, group:Quarantine) and merges
// them into one deduplicated, priority-sorted list: a device matching more
// than one reason (wandering AND in Quarantine, say) appears once with both
// reasons attached, never twice.
export function mergeAttention(groups) {
  const byId = new Map();
  const order = [];
  for (const g of groups || []) {
    for (const d of (g && g.devices) || []) {
      if (!d || !d.id) continue;
      let entry = byId.get(d.id);
      if (!entry) { entry = { device: d, reasons: [] }; byId.set(d.id, entry); order.push(entry); }
      if (!entry.reasons.includes(g.reason)) entry.reasons.push(g.reason);
    }
  }
  order.sort((a, b) => {
    const pa = Math.min(...a.reasons.map((r) => (r in REASON_PRIORITY ? REASON_PRIORITY[r] : 9)));
    const pb = Math.min(...b.reasons.map((r) => (r in REASON_PRIORITY ? REASON_PRIORITY[r] : 9)));
    if (pa !== pb) return pa - pb;
    return (Date.parse(b.device.last_seen) || 0) - (Date.parse(a.device.last_seen) || 0);
  });
  return order;
}
