const TOKEN_KEY = 'kproxy.adminToken'

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY)
}

export function setToken(token) {
  sessionStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY)
}

async function request(path, options = {}) {
  const token = getToken()
  const headers = { ...(options.headers || {}) }
  if (token) headers.Authorization = `Bearer ${token}`
  const resp = await fetch(path, { ...options, headers })
  if (resp.status === 401 || resp.status === 503) {
    clearToken()
    window.dispatchEvent(new CustomEvent('kproxy:logout'))
    throw new Error(resp.status === 503 ? 'admin API disabled on server' : 'unauthorized')
  }
  if (!resp.ok) {
    let msg = resp.statusText
    try {
      const body = await resp.json()
      if (body.error) msg = body.error
    } catch {}
    throw new Error(msg)
  }
  return resp
}

export async function login(token) {
  const resp = await fetch('/api/v1/tunnels', {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (resp.status === 401 || resp.status === 503) {
    throw new Error(resp.status === 503 ? 'admin API disabled on server' : 'unauthorized')
  }
  if (!resp.ok) throw new Error(resp.statusText)
  setToken(token)
  return token
}

export function streamURL() {
  return `/api/v1/tunnels/stream?token=${encodeURIComponent(getToken() || '')}`
}

export const getTunnels = () =>
  request('/api/v1/tunnels').then((r) => r.json())

export const listKeys = () =>
  request('/api/v1/keys').then((r) => r.json())

export const createKey = (data) =>
  request('/api/v1/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  }).then((r) => r.json())

export const revokeKey = (id) =>
  request(`/api/v1/keys/${id}`, { method: 'DELETE' })