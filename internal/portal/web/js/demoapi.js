// In-browser stand-in for the portal API, used only in demo mode so the HUD
// and Details view work with zero network calls. All data is synthetic.
import { ApiError } from './api.js';

export function createDemoApi({ getCounters, topClients, home }) {
  const rules = { block: [], allow: [], policies: { 'apple-private-relay': true } };
  let settings = { home: { ...home }, history: { mode: 'memory' } };
  const started = Date.now();
  const snapshot = () => ({ block: [...rules.block], allow: [...rules.allow], policies: { ...rules.policies } });

  return async function demoApi(path, opts = {}) {
    const method = (opts.method || 'GET').toUpperCase();
    const url = new URL(path, 'http://demo.invalid');
    const body = opts.body ? JSON.parse(opts.body) : {};
    switch (url.pathname) {
      case '/api/status': {
        const c = getCounters();
        return {
          version: 'demo', uptime_seconds: Math.floor((Date.now() - started) / 1000) + 93784,
          stats: { total: c.total, blocked: c.blocked, cached: c.cached, errors: c.errors, top_clients: topClients(), top_blocked: [
            { key: 'ads.example.net', n: Math.round(c.blocked * 0.34) }, { key: 'telemetry.example.org', n: Math.round(c.blocked * 0.27) },
            { key: 'pixel.example.com', n: Math.round(c.blocked * 0.19) }, { key: 'metrics.example.net', n: Math.round(c.blocked * 0.12) },
          ] },
          listed_domains: 184213, policies: { ...rules.policies },
          upstreams: [
            { addr: '203.0.113.53:853', healthy: true, rtt_ms: 14.2, last_error: '' },
            { addr: '203.0.113.54:853', healthy: true, rtt_ms: 19.8, last_error: '' },
          ],
          lists: [
            { name: 'Demo ads list', url: 'https://example.com/ads.txt', count: 121408, error: '' },
            { name: 'Demo trackers list', url: 'https://example.net/trackers.txt', count: 62805, error: '' },
          ],
        };
      }
      case '/api/rules':
        if (method === 'GET') return snapshot();
        if (method === 'POST') {
          const d = String(body.domain || '').trim().toLowerCase();
          if (!d) throw new ApiError('domain required', 400);
          const other = body.kind === 'block' ? 'allow' : 'block';
          rules[other] = rules[other].filter((x) => x !== d);
          if (!rules[body.kind].includes(d)) rules[body.kind].push(d);
          return snapshot();
        }
        if (method === 'DELETE') {
          const k = url.searchParams.get('kind'), d = url.searchParams.get('domain');
          if (rules[k]) rules[k] = rules[k].filter((x) => x !== d);
          return snapshot();
        }
        break;
      case '/api/policies':
        rules.policies[body.name] = !!body.enabled;
        return snapshot();
      case '/api/lists/refresh': return null;
      case '/api/settings': return settings;
      case '/api/settings/home': settings = { ...settings, home: { lat: body.lat, lon: body.lon, label: body.label || 'Home' } }; return settings;
      default: break;
    }
    throw new ApiError('not found', 404);
  };
}
