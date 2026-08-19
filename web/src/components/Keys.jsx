import { useEffect, useState } from 'react'
import { createKey, listKeys, revokeKey } from '../api.js'

const emptyForm = { name: '', ttl: '', rate: '', bandwidth: '', subdomains: '' }

export default function Keys() {
  const [keys, setKeys] = useState([])
  const [form, setForm] = useState(emptyForm)
  const [created, setCreated] = useState(null)
  const [error, setError] = useState('')

  const refresh = () => {
    listKeys().then((d) => setKeys(d.keys)).catch((e) => setError(e.message))
  }
  useEffect(refresh, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      const res = await createKey({
        name: form.name,
        ttl: form.ttl,
        rate: form.rate ? Number(form.rate) : 0,
        bandwidth: form.bandwidth,
        subdomains: form.subdomains
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      })
      setCreated(res)
      setForm(emptyForm)
      refresh()
    } catch (err) {
      setError(err.message)
    }
  }

  const revoke = async (id) => {
    try {
      await revokeKey(id)
      refresh()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <section>
      <h2>API keys</h2>
      <form className="create" onSubmit={submit}>
        <input
          placeholder="name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
        />
        <input
          placeholder="ttl (30d)"
          value={form.ttl}
          onChange={(e) => setForm({ ...form, ttl: e.target.value })}
        />
        <input
          placeholder="rate (req/s)"
          type="number"
          min="0"
          value={form.rate}
          onChange={(e) => setForm({ ...form, rate: e.target.value })}
        />
        <input
          placeholder="bandwidth (1mb)"
          value={form.bandwidth}
          onChange={(e) => setForm({ ...form, bandwidth: e.target.value })}
        />
        <input
          placeholder="subdomains (a,b)"
          value={form.subdomains}
          onChange={(e) => setForm({ ...form, subdomains: e.target.value })}
        />
        <button>Create key</button>
      </form>

      {error && <p className="error">{error}</p>}

      {created && (
        <div className="created">
          <p>
            Key created: <code>{created.key.id}</code>
          </p>
          <p>
            Secret (shown once): <code>{created.secret}</code>
          </p>
          <button onClick={() => setCreated(null)}>Dismiss</button>
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Expires</th>
            <th>Limits</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k.id} className={k.revoked ? 'revoked' : ''}>
              <td>
                <code>{k.id}</code>
              </td>
              <td>{k.name}</td>
              <td>
                {k.expires_at ? new Date(k.expires_at).toLocaleString() : 'never'}
              </td>
              <td className="muted">{describeLimits(k)}</td>
              <td>
                {k.revoked ? (
                  <span className="muted">revoked</span>
                ) : (
                  <button className="danger" onClick={() => revoke(k.id)}>
                    Revoke
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function describeLimits(k) {
  const parts = []
  const l = k.limits || {}
  if (l.requests_per_sec) parts.push(`${l.requests_per_sec} req/s`)
  if (l.bandwidth_per_sec) parts.push(`${(l.bandwidth_per_sec / 1048576).toFixed(2)} MiB/s`)
  if (l.allowed_subdomains?.length) parts.push(`sub:${l.allowed_subdomains.join(',')}`)
  return parts.join(', ') || 'unlimited'
}