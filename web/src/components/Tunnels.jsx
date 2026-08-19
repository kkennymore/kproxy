import { useEffect } from 'react'
import { getTunnels } from '../api.js'

export default function Tunnels({ tunnels, setTunnels }) {
  useEffect(() => {
    getTunnels()
      .then((d) => setTunnels(d.tunnels))
      .catch(() => {})
  }, [])

  return (
    <section>
      <h2>Tunnels</h2>
      {tunnels.length === 0 ? (
        <p className="muted">No tunnels connected.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Public URL</th>
              <th>Proto</th>
              <th>Local</th>
              <th>Agent</th>
              <th>Opened</th>
              <th>Requests</th>
              <th>Traffic</th>
            </tr>
          </thead>
          <tbody>
            {tunnels.map((t) => (
              <tr key={`${t.agent_id}:${t.id}`}>
                <td>
                  {t.public_url.startsWith('http') ? (
                    <a href={t.public_url}>{t.public_url}</a>
                  ) : (
                    t.public_url
                  )}
                </td>
                <td>{t.proto}</td>
                <td>{t.local}</td>
                <td className="muted">{t.agent_id}</td>
                <td className="muted">{new Date(t.opened_at).toLocaleTimeString()}</td>
                <td>{t.requests ?? 0}</td>
                <td className="muted">{formatBytes(t.bytes ?? 0)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n
  let i = -1
  do {
    v /= 1024
    i++
  } while (v >= 1024 && i < units.length - 1)
  return `${v.toFixed(1)} ${units[i]}`
}