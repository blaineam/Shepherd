// Virtual clock for replay. Live mode uses wall time; replay advances a
// virtual time at a chosen speed and can be paused, sought or stalled while
// data loads.

export const SPEEDS = [1, 10, 60, 300];

export class ReplayClock {
  constructor(start = 0, speed = 1) {
    this.time = start;
    this.speed = speed;
    this.playing = true;
  }

  seek(ms) { this.time = ms; }
  setSpeed(s) { if (SPEEDS.includes(s)) this.speed = s; }
  play() { this.playing = true; }
  pause() { this.playing = false; }
  toggle() { this.playing = !this.playing; return this.playing; }

  // Advance by dtMs of real time. `limit` (e.g. end of buffered data or the
  // live edge) is a ceiling; returns true if the ceiling stopped the clock.
  tick(dtMs, limit = Infinity) {
    if (!this.playing) return false;
    const next = this.time + dtMs * this.speed;
    if (next >= limit) { this.time = Math.max(this.time, limit); return true; }
    this.time = next;
    return false;
  }
}
