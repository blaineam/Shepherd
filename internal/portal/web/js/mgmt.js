// Typed wrappers around the management endpoints. Each returns parsed data
// and lets ApiError through; `unavailable(err)` recognises a server that
// predates an endpoint so views can show a friendly "not available" state.
export const unavailable = (e) => !!e && (e.status === 404 || e.status === 405 || e.status === 501);
const J = (o) => JSON.stringify(o);
const Q = (o) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v)); const s = p.toString(); return s ? '?' + s : ''; };

export function createMgmt(api) {
  const post = (p, b) => api(p, { method: 'POST', body: J(b) });
  return {
    devices: ({ q, sort, offset, limit }) => api('/api/devices' + Q({ q, sort, offset, limit })),
    device: (id) => api('/api/devices/' + encodeURIComponent(id)),
    patchDevice: (id, patch) => api('/api/devices/' + encodeURIComponent(id), { method: 'PATCH', body: J(patch) }),
    deleteDevice: (id) => api('/api/devices/' + encodeURIComponent(id), { method: 'DELETE' }),
    bulk: (req) => post('/api/devices/bulk', req),
    groups: () => api('/api/groups'),
    createGroup: (name, color) => post('/api/groups', { name, color }),
    patchGroup: (id, patch) => api('/api/groups/' + encodeURIComponent(id), { method: 'PATCH', body: J(patch) }),
    deleteGroup: (id) => api('/api/groups/' + encodeURIComponent(id), { method: 'DELETE' }),

    catalog: () => api('/api/catalog'),
    policy: () => api('/api/policy'),
    setItem: (scope, item, enabled) => post('/api/policy/items', { scope, item, enabled }),
    addRule: (scope, kind, domain) => post('/api/policy/rules', { scope, kind, domain }),
    delRule: (scope, kind, domain) => api('/api/policy/rules' + Q({ scope_kind: scope.kind, scope_id: scope.id, kind, domain }), { method: 'DELETE' }),
    setSwitch: (scope, name, enabled) => post('/api/policy/switches', { scope, name, enabled }),
    addCustomList: (body) => post('/api/policy/custom-lists', body),
    delCustomList: (id) => api('/api/policy/custom-lists/' + encodeURIComponent(id), { method: 'DELETE' }),
    refreshLists: (item) => post('/api/policy/refresh', item ? { item } : {}),

    upstreams: () => api('/api/upstreams'),
    testUpstream: (addr) => post('/api/upstreams/test', { addr }),
    addUpstream: (addr) => post('/api/upstreams', { addr }),
    removeUpstream: (addr) => api('/api/upstreams' + Q({ addr }), { method: 'DELETE' }),
    setUpstreams: (addrs) => api('/api/upstreams', { method: 'PUT', body: J({ addrs }) }),
    setBootstrap: (servers) => api('/api/upstreams/bootstrap', { method: 'PUT', body: J({ servers }) }),

    history: (params) => api('/api/history' + Q(params)),
    unlock: (passphrase) => api('/api/history/unlock', { method: 'POST', body: J({ passphrase }), keep401: true }),
    settings: () => api('/api/settings'),

    portscanStatus: () => api('/api/portscan'),
    portscanDevices: () => api('/api/portscan/devices'),
    portscanDevice: (id) => api('/api/portscan/devices/' + encodeURIComponent(id)),
    scanPorts: (deviceId) => post('/api/portscan/scan', deviceId ? { device_id: deviceId } : {}),
  };
}
