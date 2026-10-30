// LiveSource: the live event source. Prefers Server-Sent Events from
// /api/stream (same-origin cookies authenticate it) and falls back to polling
// /api/queries?after=<last id> when SSE fails, retrying SSE now and then.
// Like every source it exposes drain(nowMs, out), so the renderer cannot tell
// live data from replayed or synthetic data.
import { normalizeEntry } from './entry.js';

const CLOSED = 2; // EventSource.CLOSED

export class LiveSource {
  constructor({
    esFactory = (u) => new EventSource(u),
    fetchJson,
    url = '/api/stream',
    pollMs = 1000,
    retrySseMs = 30000,
    maxErrors = 3,
    maxBuffer = 5000,
    // Wrapped so the browser's timer functions are not called with a foreign `this`.
    timers = {
      setInterval: (f, ms) => setInterval(f, ms), clearInterval: (h) => clearInterval(h),
      setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout: (h) => clearTimeout(h),
    },
    onState = () => {},
  } = {}) {
    Object.assign(this, { esFactory, fetchJson, url, pollMs, retrySseMs, maxErrors, maxBuffer, timers, onState });
    this.kind = 'live';
    this.buf = [];
    this.lastId = 0;
    this.lastT = 0;
    this.state = 'idle';
    this.es = null;
    this.errors = 0;
    this.pollTimer = null;
    this.retryTimer = null;
    this.stopped = true;
    this.polling = false;
  }

  _set(s) {
    if (s !== this.state) { this.state = s; this.onState(s); }
  }

  // Seed after a backfill so we neither replay nor miss entries.
  seed(last) { if (Number.isFinite(last) && last > this.lastId) this.lastId = last; }

  start() {
    this.stopped = false;
    this._set('connecting');
    this._openSse();
  }

  stop() {
    this.stopped = true;
    this._closeSse();
    this._stopPolling();
    if (this.retryTimer) { this.timers.clearTimeout(this.retryTimer); this.retryTimer = null; }
    this._set('idle');
  }

  _push(raw) {
    const e = normalizeEntry(raw);
    if (!e) return;
    if (Number.isFinite(e.id)) {
      // A repeat has an old id AND an old time. A restarted server reuses low
      // ids but its entries are newer, so those are accepted and the cursor follows.
      if (e.id <= this.lastId && e.t <= this.lastT) return;
      this.lastId = e.id;
    }
    if (e.t > this.lastT) this.lastT = e.t;
    e.live = true;
    this.buf.push(e);
    if (this.buf.length > this.maxBuffer) this.buf.splice(0, this.buf.length - this.maxBuffer);
  }

  _closeSse() {
    if (this.es) { try { this.es.close(); } catch { /* ignore */ } this.es = null; }
  }

  _openSse() {
    this._closeSse();
    this.errors = 0;
    let es;
    try { es = this.esFactory(this.url); } catch { this._startPolling(); return; }
    this.es = es;
    es.addEventListener('open', () => { this.errors = 0; this._set('live'); });
    es.addEventListener('query', (ev) => {
      this.errors = 0;
      this._set('live');
      try { this._push(JSON.parse(ev.data)); } catch { /* ignore a malformed message */ }
    });
    es.onerror = () => {
      this.errors++;
      if (es.readyState === CLOSED || this.errors >= this.maxErrors) {
        this._closeSse();
        this._startPolling();
      } else {
        this._set('connecting');
      }
    };
  }

  _startPolling() {
    if (this.stopped || this.pollTimer) return;
    this._set('poll');
    this.poll();
    this.pollTimer = this.timers.setInterval(() => this.poll(), this.pollMs);
    this.retryTimer = this.timers.setTimeout(() => {
      this.retryTimer = null;
      if (this.stopped) return;
      this._stopPolling();
      this._openSse();
    }, this.retrySseMs);
  }

  _stopPolling() {
    if (this.pollTimer) { this.timers.clearInterval(this.pollTimer); this.pollTimer = null; }
  }

  async poll() {
    if (this.polling || this.stopped) return;
    this.polling = true;
    try {
      const r = await this.fetchJson('/api/queries?limit=200&after=' + this.lastId);
      for (const e of (r && r.entries) || []) this._push(e);
      if (r && Number.isFinite(r.last)) {
        if (r.last < this.lastId && !((r.entries || []).length)) this.lastId = r.last; // server restarted
        else this.seed(r.last);
      }
      if (this.state !== 'poll') this._set('poll');
    } catch (err) {
      if (err && err.message === 'unauthorized') { this._stopPolling(); this._set('idle'); } else this._set('offline');
    } finally {
      this.polling = false;
    }
  }

  drain(nowMs, out) {
    if (this.buf.length) { for (const e of this.buf) out.push(e); this.buf.length = 0; }
    return out;
  }
}
