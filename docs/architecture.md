# kproxy architecture

## Overview

kproxy has two executables sharing the core packages under `internal/`:

- **`kproxy`** — the agent CLI. Runs on the developer machine, opens one
  persistent connection to the relay, and bridges tunneled streams to local
  services.
- **`kproxyd`** — the relay server. Runs on a VPS with a public IP, terminates
  public HTTP(S)/TCP traffic, and routes each connection over the correct
  agent's tunnel.

```
+----------+          https            +----------------------+      outbound TLS      +-------------+   127.0.0.1:8082
|  client  | -------------------------> |      kproxyd         | <--------------------- |   kproxy    | ---------------> app
+----------+     public URL (443/80)    |  relay + control API |  multiplexed tunnel   |  (agent)    |     local
                                        +----------------------+                       +-------------+
```

Key property: the agent establishes the connection, so no inbound port is
needed on the dev machine, and the tunnel survives NAT, CGNAT and most
firewalls.

## Components

| Package | Responsibility |
|---|---|
| `internal/protocol` | Wire framing, stream multiplexer, control messages, byte bridge |
| `internal/relay` | Server-side tunnel registry, host/port allocation, HTTP/TCP routing |
| `internal/agent` | Agent control loop, reconnect/backoff, byte bridging |
| `internal/config` | Agent config file persistence (platform config dir, 0600) |
| `cmd/kproxy` | Agent CLI (subcommands, flags, first-run key prompt) |
| `cmd/kproxyd` | Relay daemon (HTTP/HTTPS listeners, ACME, graceful shutdown) |

## Wire protocol

The agent opens a single connection to the relay and keeps it open. All
client traffic multiplexes over it. Each message is a frame:

```
+----------------+--------+------------------+---------------------+
| payload length | type   | stream id        | payload             |
| 4 bytes BE     | 1 byte | 8 bytes BE       | length bytes        |
+----------------+--------+------------------+---------------------+
```

Frame types:

| Type | Direction | Meaning |
|---|---|---|
| `Data` | both | payload bytes for a stream |
| `Open` | relay→agent | a new public client connection; payload = tunnel id |
| `Close` | both | stream finished |
| `Control` | both | JSON control message (registration, assignment) |
| `Ping` / `Pong` | both | keepalive / liveness probe |

Streams implement `net.Conn`, so proxies are simple bidirectional byte
bridges (`io.Copy` in both directions). This makes HTTP and TCP tunnels share
one code path — the agent has **no** HTTP awareness at all.

### Control messages

- `hello` (agent→relay): version, api key, requested tunnels
  (`{id, proto, local, subdomain?, domain?}`).
- `welcome` (relay→agent): the assigned public URL for each tunnel.
- `error` (relay→agent): fatal handshake failure (e.g. bad api key).

### HTTP tunnel flow

1. Client hits `https://<hash>.domain/path`.
2. Relay looks up the virtual host, allocates a stream, sends `Open` to the
   agent.
3. Relay serializes the request (`Request.Write`) onto the stream.
4. Agent dials `127.0.0.1:8082` and bridges bytes — the request reaches the
   app untouched.
5. The app's raw response is read by the relay (`http.ReadResponse`) and
   relayed to the client (status, headers, body).

Upgrade requests (WebSocket) are detected by the `Connection: upgrade` header;
the relay hijacks the client connection and falls back to a pure byte bridge,
so websockets tunnel transparently.

### TCP tunnel flow

The relay binds a public port (default range 20000–29999), accepts clients,
and bridges each accepted connection to a stream — the same `Bridge` used for
HTTP upgrades.

## Resilience

- The agent reconnects with exponential backoff (1s → 30s cap) whenever the
  tunnel drops; streams are torn down and reopened on the new connection.
- Both sides send keepalive pings; silent half-open connections are detected
  and dropped.
- On shutdown (`SIGINT`/`SIGTERM`) the daemon drains HTTP servers and closes
  all agent connections cleanly.

## Security model

| Concern | Current (Phase 1) | Planned |
|---|---|---|
| Agent authentication | shared secret (`--admin-key`), constant-time-ish compare | API keys, argon2id-hashed, per-key limits (Phase 3) |
| Control transport | plain TCP, or TLS when `--tls-cert/--tls-key` are set | TLS by default |
| Public HTTPS | autocert (LetsEncrypt) or static certs | — |
| TLS minimum | TLS 1.2 | hardening pass (Phase 7) |
| Tunnel auth | none | `--basic-auth`, IP allowlists (Phase 5) |

Limitations to keep in mind until Phase 3: there is **no per-user key store**
yet, and the admin key is a single shared secret. Do not run with
`--admin-key ""` on a public network.

## Deployment

Systemd unit example (installed by the packaging step in Phase 6):

```ini
[Unit]
Description=kproxy relay
After=network.target

[Service]
ExecStart=/usr/bin/kproxyd --domain example.com --acme-email you@example.com --data-dir /var/lib/kproxy
Restart=always
DynamicUser=yes
StateDirectory=kproxy

[Install]
WantedBy=multi-user.target
```

Requirements:
- A domain you control, with `*.domain` and `domain` (wildcard A) pointing at
  the VPS.
- Ports 80/443 open (ACME + public HTTPS) and the control port (default 55555)
  reachable only by your agents.

## Known limitations (Phase 1)

- Flow control is per-connection backpressure; a stalled stream can slow
  others on the same tunnel. Explicit per-stream flow control is planned.
- No web dashboard, key management, or usage metrics yet (Phases 3–4).
- TCP tunnel ports are allocated automatically from a fixed range; no
  port pinning yet.

See [roadmap.md](roadmap.md) for the full phased plan.
