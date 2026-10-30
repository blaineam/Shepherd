// Authenticated fetch helper shared by the HUD and the Details view.
export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

export function createApi({ fetchFn = (...a) => fetch(...a), onUnauthorized = () => {} } = {}) {
  return async function api(path, opts = {}) {
    const res = await fetchFn(path, {
      credentials: 'same-origin',
      ...opts,
      headers: { 'X-Shepherd': '1', 'Content-Type': 'application/json', ...(opts.headers || {}) },
    });
    if (res.status === 401) { onUnauthorized(); throw new ApiError('unauthorized', 401); }
    if (!res.ok) throw new ApiError(((await res.text()) || '').trim() || res.statusText, res.status);
    return res.status === 202 || res.status === 204 ? null : res.json();
  };
}
