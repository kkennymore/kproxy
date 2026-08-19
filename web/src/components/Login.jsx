import { useState } from 'react'
import { login } from '../api.js'

export default function Login({ onLogin }) {
  const [key, setKey] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await login(key)
      onLogin(key)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login">
      <form onSubmit={submit}>
        <h1>kproxy</h1>
        <p className="muted">Control plane</p>
        <label>
          Admin key
          <input
            type="password"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            autoFocus
            placeholder="--admin-key"
          />
        </label>
        {error && <p className="error">{error}</p>}
        <button disabled={busy || !key}>{busy ? 'Checking…' : 'Log in'}</button>
      </form>
    </div>
  )
}