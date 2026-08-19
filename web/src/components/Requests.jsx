import { fmtBytes, fmtDuration } from '../hooks/useEvents.js'

export default function Requests({ events }) {
  return (
    <section>
      <h2>Live requests</h2>
      {events.length === 0 ? (
        <p className="muted">
          No requests yet. Traffic will appear here live over the event stream.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Host</th>
              <th>Method</th>
              <th>Path</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Bytes</th>
            </tr>
          </thead>
          <tbody>
            {events.map((r, i) => (
              <tr key={i}>
                <td>{new Date(r.time).toLocaleTimeString()}</td>
                <td>{r.host}</td>
                <td>{r.method}</td>
                <td>{r.path}</td>
                <td className={`status s${Math.floor(r.status / 100)}`}>{r.status}</td>
                <td>{fmtDuration(r.duration)}</td>
                <td>{fmtBytes(r.bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}