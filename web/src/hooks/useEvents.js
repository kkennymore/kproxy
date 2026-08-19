import { useEffect, useState } from 'react'
import { streamURL } from '../api.js'

export function useEvents() {
  const [events, setEvents] = useState([])
  const [tunnels, setTunnels] = useState([])

  useEffect(() => {
    const es = new EventSource(streamURL())

    es.addEventListener('tunnel_open', (e) => {
      const t = JSON.parse(e.data)
      setTunnels((prev) => {
        if (prev.some((x) => x.id === t.id && x.agent_id === t.agent_id)) return prev
        return [t, ...prev]
      })
    })

    es.addEventListener('tunnel_close', (e) => {
      const t = JSON.parse(e.data)
      setTunnels((prev) => prev.filter((x) => !(x.id === t.id && x.agent_id === t.agent_id)))
    })

    es.addEventListener('request', (e) => {
      const r = JSON.parse(e.data)
      setEvents((prev) => [r, ...prev].slice(0, 200))
    })

    es.onerror = () => {
      // EventSource reconnects automatically.
    }

    return () => es.close()
  }, [])

  return { events, tunnels, setTunnels }
}

export function fmtDuration(ns) {
  if (ns == null) return '—'
  const ms = ns / 1e6
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

export function fmtBytes(n) {
  if (n == null) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`
}