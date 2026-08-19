import { useEffect, useState } from 'react'
import Login from './components/Login.jsx'
import Tunnels from './components/Tunnels.jsx'
import Requests from './components/Requests.jsx'
import Keys from './components/Keys.jsx'
import { getToken, clearToken } from './api.js'
import { useEvents } from './hooks/useEvents.js'

const TABS = ['tunnels', 'requests', 'keys']

export default function App() {
  const [token, setToken] = useState(getToken())
  const [tab, setTab] = useState('tunnels')
  const { events, tunnels, setTunnels } = useEvents()

  useEffect(() => {
    const onLogout = () => {
      clearToken()
      setToken(null)
    }
    window.addEventListener('kproxy:logout', onLogout)
    return () => window.removeEventListener('kproxy:logout', onLogout)
  }, [])

  if (!token) return <Login onLogin={setToken} />

  return (
    <div className="app">
      <header>
        <h1>kproxy</h1>
        <nav>
          {TABS.map((name) => (
            <button
              key={name}
              className={tab === name ? 'active' : ''}
              onClick={() => setTab(name)}
            >
              {name.charAt(0).toUpperCase() + name.slice(1)}
            </button>
          ))}
        </nav>
        <button className="logout" onClick={onLogout}>
          Log out
        </button>
      </header>
      <main>
        {tab === 'tunnels' && <Tunnels tunnels={tunnels} setTunnels={setTunnels} />}
        {tab === 'requests' && <Requests events={events} />}
        {tab === 'keys' && <Keys />}
      </main>
    </div>
  )
}