import { applyModeLocal } from './wander.js';

// Bulk device operations: local application (optimistic UI) and undo plans.

export function normTag(t) { return String(t || '').trim().toLowerCase().replace(/\s+/g, '-').slice(0, 32); }
export function parseTags(s) {
  return [...new Set(String(s || '').split(/[,\n]/).map(normTag).filter(Boolean))];
}

// Returns a new device with the op applied (mirrors the server semantics).
export function applyBulkLocal(d, req) {
  const n = { ...d };
  switch (req.op) {
    case 'assign_group': n.groups = (d.groups || []).includes(req.group_id) ? d.groups : [...(d.groups || []), req.group_id]; break;
    case 'remove_group': n.groups = (d.groups || []).filter((g) => g !== req.group_id); break;
    case 'set_excluded': n.excluded = !!req.excluded; if (n.excluded) { n.wandering = false; delete n.wandering_until; } break;
    case 'set_wandering': return applyModeLocal(d, { wandering: !!req.wandering, wandering_minutes: req.wandering_minutes });
    case 'set_watch': n.watch = req.watch; break;
    case 'set_tags': {
      const rm = new Set((req.remove_tags || []).map(normTag));
      const tags = (d.tags || []).filter((t) => !rm.has(t));
      for (const t of req.add_tags || []) if (!tags.includes(normTag(t))) tags.push(normTag(t));
      n.tags = tags; break;
    }
    default: break;
  }
  return n;
}

// Builds the bulk requests that restore `before` (the devices prior to the op).
// Returns null when the op cannot be undone (delete).
export function planUndo(req, before) {
  const out = [];
  const idsWhere = (fn) => before.filter(fn).map((d) => d.id);
  const push = (r, ids) => { if (ids.length) out.push({ ...r, ids }); };
  switch (req.op) {
    case 'assign_group':
      push({ op: 'remove_group', group_id: req.group_id }, idsWhere((d) => !(d.groups || []).includes(req.group_id)));
      break;
    case 'remove_group':
      push({ op: 'assign_group', group_id: req.group_id }, idsWhere((d) => (d.groups || []).includes(req.group_id)));
      break;
    case 'set_excluded':
      push({ op: 'set_excluded', excluded: true }, idsWhere((d) => !!d.excluded && !req.excluded));
      push({ op: 'set_excluded', excluded: false }, idsWhere((d) => !d.excluded && !!req.excluded));
      break;
    case 'set_wandering': {
      const was = before.filter((d) => !!d.wandering);
      const ex = before.filter((d) => !d.wandering && !!d.excluded);
      push({ op: 'set_wandering', wandering: true }, was.filter(() => !!req.wandering === false).map((d) => d.id));
      push({ op: 'set_wandering', wandering: false }, before.filter((d) => !d.wandering && req.wandering).map((d) => d.id));
      push({ op: 'set_excluded', excluded: true }, ex.filter(() => !!req.wandering).map((d) => d.id));
      break;
    }
    case 'set_watch': {
      // One request per distinct previous position, so an undo puts every
      // device back where it was rather than on one shared value.
      for (const was of ['auto', 'on', 'off']) {
        push({ op: 'set_watch', watch: was }, idsWhere((d) => (d.watch || 'auto') === was && was !== req.watch));
      }
      break;
    }
    case 'set_tags': {
      for (const t of req.add_tags || []) {
        const nt = normTag(t);
        push({ op: 'set_tags', remove_tags: [nt] }, idsWhere((d) => !(d.tags || []).includes(nt)));
      }
      for (const t of req.remove_tags || []) {
        const nt = normTag(t);
        push({ op: 'set_tags', add_tags: [nt] }, idsWhere((d) => (d.tags || []).includes(nt)));
      }
      break;
    }
    default: return null;
  }
  return out;
}

export function describeBulk(req, n, groupName = (id) => id) {
  const w = n === 1 ? '1 device' : n.toLocaleString() + ' devices';
  switch (req.op) {
    case 'assign_group': return `Added ${w} to ${groupName(req.group_id)}`;
    case 'remove_group': return `Removed ${w} from ${groupName(req.group_id)}`;
    case 'set_excluded': return `${req.excluded ? 'Excluded' : 'Included'} ${w}`;
    case 'set_tags': return `Updated tags on ${w}`;
    case 'set_watch': return req.watch === 'off' ? `Watch mode off for ${w}` : req.watch === 'on' ? `${w} always watched` : `${w} back to automatic watching`;
    case 'set_wandering': return req.wandering ? `${w} set to wandering` + (req.wandering_minutes > 0 ? ' for ' + (req.wandering_minutes >= 60 ? req.wandering_minutes / 60 + ' h' : req.wandering_minutes + ' min') : '') : `${w} back to protected`;
    case 'delete': return `Deleted ${w}`;
    default: return 'Done';
  }
}
