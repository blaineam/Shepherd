// ReplaySource: reusable "abstract event source" for past time ranges. It
// pulls chunks from any async loader(from, to, limit) -> {entries}, and hands
// entries to the renderer as a virtual clock passes them. The same renderer
// consumes live SSE events and replayed history through drain(nowMs, out).

export class ReplaySource {
  constructor({ load, chunkMs = 30 * 60 * 1000, limit = 5000, prefetch = 0.3, edgeGapMs = 2000, bound = () => Date.now() } = {}) {
    this.load = load;
    this.chunkMs = chunkMs;
    this.limit = limit;
    this.prefetch = prefetch;
    this.edgeGapMs = edgeGapMs; // within this of the live edge there is nothing worth fetching
    this.bound = bound; // upper edge of history (live edge)
    this.kind = 'replay';
    this.buf = [];
    this.i = 0;
    this.loadedUntil = 0;
    this.loading = false;
    this.gen = 0;
    this.error = null;
    this.onChange = null;
  }

  setChunk(ms) { this.chunkMs = Math.max(60 * 1000, ms); }

  seek(t) {
    this.gen++;
    this.buf = [];
    this.i = 0;
    this.loadedUntil = t;
    this.loading = false;
    this.error = null;
    return this._fetch(t);
  }

  stop() { this.gen++; this.buf = []; this.i = 0; this.loading = false; }

  async _fetch(from) {
    const edge = this.bound();
    if (from >= edge) { this.loadedUntil = edge; return; }
    const to = Math.min(edge, from + this.chunkMs);
    const gen = this.gen;
    this.loading = true;
    try {
      const res = await this.load(from, to, this.limit);
      if (gen !== this.gen) return;
      const entries = (res && res.entries) || [];
      entries.sort((a, b) => a.t - b.t);
      // Trim consumed entries so the buffer stays small on long replays.
      if (this.i > 0) { this.buf = this.buf.slice(this.i); this.i = 0; }
      for (const e of entries) if (e.t >= from) this.buf.push(e);
      // If the chunk hit the limit we only know the data up to its last entry.
      this.loadedUntil = entries.length >= this.limit ? entries[entries.length - 1].t : to;
      this.error = null;
    } catch (err) {
      if (gen !== this.gen) return;
      this.error = err;
      this.loadedUntil = to; // do not stall forever on a failing endpoint
    } finally {
      if (gen === this.gen) { this.loading = false; if (this.onChange) this.onChange(); }
    }
  }

  // Highest virtual time the clock may reach right now without outrunning data.
  get ceiling() {
    return this.loadedUntil < this.bound() - this.edgeGapMs ? this.loadedUntil : Infinity;
  }

  drain(nowMs, out) {
    const buf = this.buf;
    while (this.i < buf.length && buf[this.i].t <= nowMs) out.push(buf[this.i++]);
    if (!this.loading && this.loadedUntil < this.bound() - this.edgeGapMs && nowMs > this.loadedUntil - this.chunkMs * this.prefetch) {
      this._fetch(this.loadedUntil);
    }
    return out;
  }
}
