/* global window, fetch */
// Shared API wrapper for both insecure.html and secure.html (vanilla JS + Fetch API)
(function () {
  'use strict';

  const DEFAULT_TIMEOUT_MS = 10_000;

  async function fetchJson(path, { method = 'GET', body = undefined, headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(path, {
        method,
        headers: {
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
        credentials: 'same-origin',
      });

      let data = null;
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        data = await res.json();
      } else {
        data = { raw: await res.text() };
      }

      if (!res.ok) {
        const msg = (data && (data.error || data.message)) || `Request failed (${res.status})`;
        const err = new Error(msg);
        err.status = res.status;
        err.data = data;
        throw err;
      }

      return data;
    } finally {
      clearTimeout(t);
    }
  }

  const Api = {
    fetchJson,

    // INSECURE demo endpoints (intentionally vulnerable on the server)
    insecureLogin: (payload) => fetchJson('/api/insecure/login', { method: 'POST', body: payload }),
    insecureComment: (payload) => fetchJson('/api/insecure/comment', { method: 'POST', body: payload }),
    insecureGetComments: () => fetchJson('/api/insecure/comments'),

    // SECURE endpoints
    secureRegister: (payload) => fetchJson('/api/secure/register', { method: 'POST', body: payload }),
    secureLogin: (payload) => fetchJson('/api/secure/login', { method: 'POST', body: payload }),
    secureLogout: () => fetchJson('/api/secure/logout', { method: 'POST', body: {} }),
    secureComment: (payload) => fetchJson('/api/secure/comment', { method: 'POST', body: payload }),
    secureGetComments: () => fetchJson('/api/secure/comments'),
    secureMe: () => fetchJson('/api/secure/me'),

    // Admin (attack logs + stats)
    adminGetLogs: (limit = 200) => fetchJson(`/api/admin/logs?limit=${encodeURIComponent(String(limit))}`),
    adminGetStats: (windowHours = 24) => fetchJson(`/api/admin/stats?window_hours=${encodeURIComponent(String(windowHours))}`),
  };

  window.CyberDemoApi = Api;
})();

