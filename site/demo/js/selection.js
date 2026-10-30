// Selection model for a long list: individual ids, shift-click ranges and an
// "all matches" mode that remembers unchecked exceptions.
export class Selection {
  constructor() { this.clear(); }

  clear() {
    this.ids = new Set();
    this.allMatches = false;
    this.excluded = new Set();
    this.anchor = -1;
    this.total = 0;
  }

  has(id) { return this.allMatches ? !this.excluded.has(id) : this.ids.has(id); }

  count() { return this.allMatches ? Math.max(0, this.total - this.excluded.size) : this.ids.size; }

  get empty() { return this.count() === 0; }

  set(id, on) {
    if (this.allMatches) { if (on) this.excluded.delete(id); else this.excluded.add(id); }
    else if (on) this.ids.add(id); else this.ids.delete(id);
  }

  toggle(id, index = -1) {
    const on = !this.has(id);
    this.set(id, on);
    this.anchor = index;
    return on;
  }

  // Shift-click: apply the anchor row's new state to everything between.
  range(orderedIds, index) {
    if (this.anchor < 0 || this.anchor >= orderedIds.length) return this.toggle(orderedIds[index], index);
    const [a, b] = this.anchor < index ? [this.anchor, index] : [index, this.anchor];
    for (let i = a; i <= b; i++) if (orderedIds[i] !== undefined) this.set(orderedIds[i], true);
    return true;
  }

  selectPage(ids) {
    this.allMatches = false; this.excluded = new Set();
    for (const id of ids) this.ids.add(id);
  }

  selectAllMatches(total) {
    this.allMatches = true; this.excluded = new Set(); this.ids = new Set(); this.total = total;
  }

  pageState(ids) {
    if (!ids.length) return 'none';
    let n = 0;
    for (const id of ids) if (this.has(id)) n++;
    return n === 0 ? 'none' : n === ids.length ? 'all' : 'some';
  }

  setTotal(total) { this.total = total; }

  // Drops ids that no longer exist (after a delete).
  forget(ids) {
    for (const id of ids) { this.ids.delete(id); this.excluded.delete(id); }
  }

  // Resolves to explicit ids. fetchAll(): Promise<id[]> is called for all-matches mode.
  async resolve(fetchAll) {
    if (!this.allMatches) return [...this.ids];
    return (await fetchAll()).filter((id) => !this.excluded.has(id));
  }
}
