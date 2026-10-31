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
    addRule: (scope, kind, domain, schedule) => post('/api/policy/rules', { scope, kind, domain, schedule }),
    delRule: (scope, kind, domain) => api('/api/policy/rules' + Q({ scope_kind: scope.kind, scope_id: scope.id, kind, domain }), { method: 'DELETE' }),
    setSwitch: (scope, name, enabled) => post('/api/policy/switches', { scope, name, enabled }),
    setMode: (scope, mode) => post('/api/policy/mode', { scope, mode }),
    addCustomList: (body) => post('/api/policy/custom-lists', body),
    delCustomList: (id) => api('/api/policy/custom-lists/' + encodeURIComponent(id), { method: 'DELETE' }),
    refreshLists: (item) => post('/api/policy/refresh', item ? { item } : {}),

    contacts: () => api('/api/accountability/contacts'),
    addContact: (name, email) => post('/api/accountability/contacts', { name, email }),
    deleteContact: (id) => api('/api/accountability/contacts/' + encodeURIComponent(id), { method: 'DELETE' }),
    subscriptions: (contactId) => api('/api/accountability/subscriptions' + Q({ contact_id: contactId })),
    addSubscription: (body) => post('/api/accountability/subscriptions', body),
    deleteSubscription: (id) => api('/api/accountability/subscriptions/' + encodeURIComponent(id), { method: 'DELETE' }),
    smtpRelay: () => api('/api/accountability/smtp'),
    setSMTPRelay: (body) => api('/api/accountability/smtp', { method: 'PUT', body: J(body) }),
    clearSMTPRelay: () => api('/api/accountability/smtp', { method: 'DELETE' }),

    geoBlock: () => api('/api/geoblock'),
    setCountries: (scope, countries) => post('/api/geoblock', { scope, countries }),

    upstreams: () => api('/api/upstreams'),
    testUpstream: (addr) => post('/api/upstreams/test', { addr }),
    addUpstream: (addr) => post('/api/upstreams', { addr }),
    removeUpstream: (addr) => api('/api/upstreams' + Q({ addr }), { method: 'DELETE' }),
    setUpstreams: (addrs) => api('/api/upstreams', { method: 'PUT', body: J({ addrs }) }),
    setBootstrap: (servers) => api('/api/upstreams/bootstrap', { method: 'PUT', body: J({ servers }) }),

    history: (params) => api('/api/history' + Q(params)),
    unlock: (passphrase) => api('/api/history/unlock', { method: 'POST', body: J({ passphrase }), keep401: true }),
    settings: () => api('/api/settings'),

    importEeroStart: (login) => post('/api/import/eero/start', { login }),
    importEeroVerify: (sessionId, code) => post('/api/import/eero/verify', { session_id: sessionId, code }),
    importEeroPreview: (sessionId, networkId, overwriteNames) => post('/api/import/eero/preview', { session_id: sessionId, network_id: networkId, overwrite_names: overwriteNames }),
    importEeroApply: (sessionId) => post('/api/import/eero/apply', { session_id: sessionId }),
    importEeroCancel: (sessionId) => post('/api/import/eero/cancel', { session_id: sessionId }),
    importCSVPreview: (csv, overwriteNames) => post('/api/import/csv/preview', { csv, overwrite_names: overwriteNames }),
    importCSVApply: (csv, overwriteNames) => post('/api/import/csv/apply', { csv, overwrite_names: overwriteNames }),

    alarms: (params) => api('/api/alarms' + Q(params)),
    alarm: (id) => api('/api/alarms/' + encodeURIComponent(id)),
    patchAlarm: (id, state) => api('/api/alarms/' + encodeURIComponent(id), { method: 'PATCH', body: J({ state }) }),
    deleteAlarm: (id) => api('/api/alarms/' + encodeURIComponent(id), { method: 'DELETE' }),
    muteAlarm: (id, duration) => post('/api/alarms/' + encodeURIComponent(id) + '/mute', duration),
    alarmsBulk: (req) => post('/api/alarms/bulk', req),
    undoAlarms: (handle) => post('/api/alarms/undo', { handle }),
    alarmsSummary: () => api('/api/alarms/summary'),
    alarmTypes: () => api('/api/alarms/types'),
    alarmRules: (all) => api('/api/alarms/rules' + Q({ all: all ? '1' : '' })),
    createAlarmRule: (body) => post('/api/alarms/rules', body),
    deleteAlarmRule: (id) => api('/api/alarms/rules/' + encodeURIComponent(id), { method: 'DELETE' }),

    portscanStatus: () => api('/api/portscan'),
    portscanDevices: () => api('/api/portscan/devices'),
    portscanDevice: (id) => api('/api/portscan/devices/' + encodeURIComponent(id)),
    scanPorts: (deviceId) => post('/api/portscan/scan', deviceId ? { device_id: deviceId } : {}),

    setLockingSettings: (idleLockMinutes) => post('/api/settings/locking', { idle_lock_minutes: idleLockMinutes }),
    setPIN: (pin) => post('/api/pin', { pin }),
    trustPIN: (pin) => post('/api/pin/trust', { pin }),
    clearPIN: () => api('/api/pin', { method: 'DELETE' }),
    trustedDevices: () => api('/api/trusted-devices'),
    revokeTrustedDevice: (id) => api('/api/trusted-devices/' + encodeURIComponent(id), { method: 'DELETE' }),
    lock: () => post('/api/lock', {}),
    passkeys: () => api('/api/passkeys'),
    beginPasskeyRegistration: (name) => post('/api/passkeys/register/begin', { name }),
    finishPasskeyRegistration: (credential) => post('/api/passkeys/register/finish', credential),
    renamePasskey: (id, name) => api('/api/passkeys/' + encodeURIComponent(id), { method: 'PATCH', body: J({ name }) }),
    revokePasskey: (id) => api('/api/passkeys/' + encodeURIComponent(id), { method: 'DELETE' }),

    vulnscanStatus: () => api('/api/vulnscan'),
    vulnscanDevices: () => api('/api/vulnscan/devices'),
    vulnscanDevice: (id) => api('/api/vulnscan/devices/' + encodeURIComponent(id)),
    scanVulns: (deviceId) => post('/api/vulnscan/scan', deviceId ? { device_id: deviceId } : {}),

    nethealthStatus: () => api('/api/nethealth'),
    nethealthSeries: (params) => api('/api/nethealth/series' + Q(params)),
    nethealthBufferbloat: (params) => api('/api/nethealth/bufferbloat' + Q(params)),
    nethealthProbeNow: () => post('/api/nethealth/probe', {}),
    nethealthBufferbloatRun: () => post('/api/nethealth/bufferbloat/run', {}),

    reverseProxy: () => api('/api/reverseproxy'),
    proxyHosts: () => api('/api/reverseproxy/hosts'),
    addProxyHost: (body) => post('/api/reverseproxy/hosts', body),
    updateProxyHost: (id, body) => api('/api/reverseproxy/hosts/' + encodeURIComponent(id), { method: 'PUT', body: J(body) }),
    deleteProxyHost: (id) => api('/api/reverseproxy/hosts/' + encodeURIComponent(id), { method: 'DELETE' }),
    dnsProvider: () => api('/api/dns-provider'),
    setDNSProvider: (body) => api('/api/dns-provider', { method: 'PUT', body: J(body) }),
    clearDNSProvider: () => api('/api/dns-provider', { method: 'DELETE' }),
  };
}
