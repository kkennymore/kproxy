# kproxy

**kproxy** is a self-hosted, open-source tunnel that exposes local development
services to the internet **without port forwarding**. Run `kproxy http 8082`
on your machine and instantly get a public HTTPS URL you can share with a
client — exactly like ngrok, but self-hosted and fully under your control.

```
Client browser ── https://ab12cd.yourdomain.com ──► [kproxyd server] (VPS)
                                                     │  persistent outbound tunnel
                                                   [kproxy agent]  (dev machine)
                                                     │
                                                  localhost:8082  (your app)
```

The agent only ever makes **outbound** connections to the server, so it works
behind NAT, CGNAT and almost any firewall. No router configuration, no public
IP on the dev machine, no static port mapping.

---

## Table of contents

- [How it works](#how-it-works)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage reference](#usage-reference)
  - [kproxy (agent CLI)](#kproxy-agent-cli)
  - [kproxyd (relay server)](#kproxyd-relay-server)
- [Examples](#examples)
- [Configuration](#configuration)
- [TLS and domains](#tls-and-domains)
- [Security model](#security-model)
- [Deployment](#deployment)
- [Development](#development)
- [Status and roadmap](#status-and-roadmap)
- [License](#license)

---

## How it works

kproxy is a client-server pair connected by a single persistent, multiplexed
connection.

1. **The server** (`kproxyd`) runs on a machine with a public IP — typically a
   cheap VPS. It owns a domain (e.g. `yourdomain.com`) and terminates public
   HTTP(S) and TCP traffic on ports 80/443 and a TCP port range.
2. **The agent** (`kproxy`) runs on the developer's machine. It dials the
   server once and keeps the connection open. It requests one or more tunnels,
   each pointing at a local service such as `127.0.0.1:8082`.
3. The server assigns each tunnel a public endpoint — by default a random hash
   subdomain (`https://ab12cd.yourdomain.com`), or a custom subdomain/domain if
   you ask for one.
4. When a client requests that endpoint, the server opens a **stream** over
   the agent's existing connection and bridges the traffic: bytes flow
   client → server → tunnel → agent → local app, and back.

Because all of this rides on the agent's single outbound connection, the
developer never needs to open a port or configure their router. The whole
system is multiplexed — many clients can be served concurrently over one
tunnel connection, and many tunnels can run from one agent process.

For the full protocol and implementation details, see
[`docs/architecture.md`](docs/architecture.md) and the
[developer guide](README.md).

---

## Features

### Tunnels
- **HTTP tunnels** — expose web apps, APIs, and static sites:
  `kproxy http 8082`.
- **TCP tunnels** — expose any raw TCP service (SSH, databases, game servers,
  VNC): `kproxy tcp 22`.
- **WebSocket support** — WebSocket and other HTTP upgrade requests
  (`Connection: upgrade`) are tunneled transparently with no extra config.
- **Multiple tunnels** — an agent can open several tunnels at once (HTTP and
  TCP) from one process.

### Public endpoints
- **Random hash subdomains** by default: `https://7f3a9c21.yourdomain.com`.
- **Custom subdomains**: `kproxy http 8082 --subdomain myapp` →
  `https://myapp.yourdomain.com`.
- **Custom domains**: `kproxy http 8082 --domain app.client.com` — your client
  points their domain at your server and sees the app on their own URL.
- **TCP ports** are allocated automatically from a configurable public range
  (default `20000–29999`): `tcp://yourdomain.com:20000`.

### Reliability
- **Automatic reconnect** with exponential backoff (1s → 30s) when the network
  blips; tunnels are re-registered transparently.
- **Keepalive pings** on both sides detect and drop half-open connections.
- **Graceful shutdown** on `Ctrl+C` / `SIGTERM` for both the agent and server.

### Security
- **Agent authentication** via an API key or a shared admin key.
- **HTTPS** on public endpoints via automatic LetsEncrypt certificates
  (ACME) or your own certificates.
- **TLS 1.2+** minimum, **first-run key prompt** that stores your key in a
  per-user config file with restrictive permissions.
- Local app is only reachable through the tunnel; nothing inbound is exposed
  on the dev machine.

### Operations
- **JSON or human-readable logs** (`--json`, `--verbose`).
- **Single static binary** — no runtime dependencies, no installer cruft.
- **Cross-platform** — Windows, Linux (deb/rpm), macOS; amd64 and arm64.
- **Self-contained** — the only third-party dependency is Google's
  `x/crypto` (ACME client), pinned and vendored at build time.

---

## Requirements

| Component | Requirement |
|---|---|
| **Server** | A machine with a public IP (VPS), ports 80/443 open, and a domain you control with a wildcard `*.domain` A/AAAA record pointing at it. Linux recommended. |
| **Agent** | Any machine with internet access (dev laptop, CI runner). No public IP, no router changes needed. |
| **Build** | Go ≥ 1.22 (only needed to build from source; released binaries need nothing). |

---

## Installation

### From source

```sh
git clone <your-repo-url> kproxy
cd kproxy
make build            # builds bin/kproxy and bin/kproxyd
```

Or install to your Go bin directory:

```sh
go install ./cmd/kproxy ./cmd/kproxyd
```

### Prebuilt binaries

Prebuilt installers and binaries (Windows MSI/zip, Linux deb/rpm/tar.gz, macOS
pkg/zip) are planned for Phase 6 of the roadmap. Until then, build from
source.

---

## Quick start

### 1. Start the server (on your VPS)

```sh
kproxyd \
  --domain yourdomain.com \
  --http-addr :80 \
  --https-addr :443 \
  --acme-email you@example.com \
  --admin-key "choose-a-strong-secret"
```

What this does:
- Listens for agent connections on the control port (`:55555` by default).
- Serves public HTTPS on `:443` (automatic LetsEncrypt certs via `--acme-email`)
  and redirects `:80` to HTTPS.
- Requires agents to present `--admin-key`.

> **No domain yet?** You can run in dev mode without HTTPS:
> `kproxyd --domain localhost --http-addr :8080 --https-addr "" --admin-key test`

### 2. Start the agent (on your dev machine)

```sh
kproxy http 8082 --server http://your-vps:55555 --api-key "choose-a-strong-secret"
```

If you omit `--api-key`, kproxy prompts for one on first run and stores it in
your config file so future runs need no arguments:

```sh
kproxy http 8082 --server http://your-vps:55555
```

### 3. Share the URL

```
Tunnel online on yourdomain.com
  https://7f3a9c21.yourdomain.com
```

Anyone who can reach that URL now sees your local app exactly as if it were
hosted. Share it with your client — that's the whole point.

---

## Usage reference

### kproxy (agent CLI)

```
kproxy http <port> [flags]     expose an HTTP service
kproxy tcp <port>  [flags]     expose a raw TCP service
```

| Flag | Default | Description |
|---|---|---|
| `--subdomain NAME` | random | Request a specific subdomain (`myapp` → `myapp.domain`) |
| `--domain HOST` | — | Expose on a custom domain you control (`app.client.com`) |
| `--local-host HOST` | `127.0.0.1` | Local host/interface to forward to |
| `--server URL` | `http://localhost:55555` | Relay server endpoint (`http://` or `https://`) |
| `--api-key KEY` | — | API key for the relay (prompted on first run if absent) |
| `--config PATH` | platform default | Config file to read/write instead of the default |
| `--verbose` | off | Debug-level logging |
| `--json` | off | JSON log output instead of human-readable |

Environment variables (used when the flag is not set): `KPROXY_SERVER`,
`KPROXY_API_KEY`.

Global commands: `kproxy --version`, `kproxy help`.

### kproxyd (relay server)

```
kproxyd --domain example.com [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--domain` | *(required)* | Base domain for tunnel subdomains and TCP URLs |
| `--control-addr` | `:55555` | Listen address for agent control connections |
| `--http-addr` | `:80` | Public HTTP listener (ACME challenges + redirect to HTTPS) |
| `--https-addr` | `:443` | Public HTTPS listener; set `""` to disable HTTPS |
| `--admin-key` | *(empty)* | Shared secret agents must present; empty allows all (dev only) |
| `--tcp-port-range` | `20000-29999` | Public port range allocated to TCP tunnels |
| `--acme-email` | — | Email for LetsEncrypt; enables automatic certificates |
| `--tls-cert` / `--tls-key` | — | Paths to your own certificate and private key |
| `--data-dir` | `./data` | Directory for the certificate cache and runtime state |
| `--verbose` | off | Debug-level logging |
| `--json` | off | JSON log output |
| `--version` | — | Print version and exit |

> Exactly one of `--acme-email` or `--tls-cert/--tls-key` is required when
> `--https-addr` is enabled.

---

## Examples

### Expose a web app with a random URL

```sh
kproxy http 3000 --server https://relay.example.com:55555
# → https://b8e4d7a1.relay.example.com
```

### Expose with a memorable subdomain

```sh
kproxy http 3000 --subdomain checkout --server https://relay.example.com:55555
# → https://checkout.relay.example.com
```

### Expose on a client's own domain

Your client adds `app.client.com` → your server IP, then:

```sh
kproxy http 3000 --domain app.client.com --server https://relay.example.com:55555
# → https://app.client.com
```

### Expose an SSH server over TCP

```sh
kproxy tcp 22 --server https://relay.example.com:55555
# → tcp://relay.example.com:20123  (ssh user@relay.example.com -p 20123)
```

### Expose a database

```sh
kproxy tcp 3306 --server https://relay.example.com:55555
# → tcp://relay.example.com:20004
```

### WebSockets over HTTP tunnel

No special flag — a WebSocket app on your local server just works:

```sh
kproxy http 8080 --subdomain live --server https://relay.example.com:55555
# connect client-side to wss://live.relay.example.com
```

### Multiple tunnels from one agent

```sh
# run several kproxy commands in parallel, or see the roadmap for a
# tunnel-config-file to start them all at once
kproxy http 8082 --subdomain api &
kproxy tcp 3306 &
```

---

## Configuration

The agent stores its credentials in a per-user JSON config file:

| OS | Path |
|---|---|
| Linux | `~/.config/kproxy/config.json` |
| macOS | `~/Library/Application Support/kproxy/config.json` |
| Windows | `%AppData%\kproxy\config.json` |

```json
{
  "server_url": "https://relay.example.com:55555",
  "api_key": "your-secret-key"
}
```

The file is created with restrictive permissions (`0600`). A custom location
can be passed with `--config`.

**Precedence** (first match wins): command-line flag → environment variable →
config file → default / interactive prompt.

On the **first run without `--api-key`**, kproxy prompts interactively and
saves what you enter, so subsequent runs need no credentials:

```sh
$ kproxy http 8082 --server https://relay.example.com:55555
kproxy has no api key for https://relay.example.com:55555.
Ask the server operator for a key, then enter it here: ********
credentials saved.
Tunnel online on relay.example.com
  https://7f3a9c21.relay.example.com
```

---

## TLS and domains

### Automatic certificates (ACME / LetsEncrypt)

Pass `--acme-email` to the server. The server obtains and caches a certificate
for every tunnel host automatically (via HTTP-01 challenges on port 80).
Certs are cached in `--data-dir` and renewed automatically.

Requirements: ports 80 and 443 reachable from the internet, and a wildcard
`*.yourdomain.com` record pointing at the server. The daemon refuses to issue
certs for hosts outside your domain.

### Your own certificates (wildcard certs)

If you have a wildcard certificate (e.g. obtained with a DNS-01 challenge from
LetsEncrypt or a commercial CA), use static certs — no port 80 needed:

```sh
kproxyd --domain yourdomain.com \
  --tls-cert /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

When static certs are configured, the **control listener** (agent connections)
is also wrapped in TLS, so agents can connect with
`--server https://yourdomain.com:55555`.

### Dev mode (no TLS)

```sh
kproxyd --domain localhost --http-addr :8080 --https-addr "" --admin-key test
kproxy http 8082 --server http://localhost:55555 --api-key test
```

Public URLs look like `http://7f3a9c21.localhost:8080`. To test from a browser
locally, add a hosts-file entry (or use a domain that resolves to 127.0.0.1)
so `*.yourdomain` reaches your machine.

---

## Security model

| Concern | Approach |
|---|---|
| Agent authentication | API key / shared `--admin-key` verified on every registration. |
| Key storage | Per-user config file, `0600` permissions; OS keyring planned. |
| Public endpoints | HTTPS with auto-rotating LetsEncrypt certs or your own certs. |
| Transport | Control connections optionally TLS; tunnel traffic rides that encrypted channel. |
| TLS version | Minimum TLS 1.2. |
| Local exposure | The agent dials the local service; nothing is ever exposed inbound on the dev machine. |
| Server hardening | Firewall the control port (`:55555`) to only your agents; keep `--admin-key` strong. |

**Before Phase 3** (real per-user API keys), `--admin-key` is a single shared
secret. Do not run the server with `--admin-key ""` on a public network.

Planned hardening: per-user API keys with hashing and expiry, per-key rate and
bandwidth limits, per-tunnel basic auth and IP allowlists — see the roadmap.

---

## Deployment

### DNS

Point a wildcard record at the server so every hash subdomain resolves to it:

```
*.yourdomain.com   A   <server-ip>
yourdomain.com     A   <server-ip>
```

(Add an AAAA record for IPv6, if applicable.)

### systemd (Linux VPS)

Create `/etc/systemd/system/kproxyd.service`:

```ini
[Unit]
Description=kproxy relay server
After=network.target

[Service]
ExecStart=/usr/local/bin/kproxyd --domain yourdomain.com --acme-email you@example.com --admin-key "$KPROXY_ADMIN_KEY" --data-dir /var/lib/kproxy
Restart=always
RestartSec=3
Environment=KPROXY_ADMIN_KEY=choose-a-strong-secret
DynamicUser=yes
StateDirectory=kproxy
NoNewPrivileges=yes
ProtectSystem=strict
ReadOnlyPaths=/usr/local/bin

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now kproxyd
```

### Firewall

| Port | Purpose |
|---|---|
| `80/tcp` | ACME challenges + HTTP→HTTPS redirect |
| `443/tcp` | Public HTTPS traffic |
| `20000–29999/tcp` | Public TCP tunnels (your configured range) |
| `55555/tcp` | Agent control connections — **restrict to your agents if possible** |

### Docker

A multi-arch Docker image is planned (Phase 6). Until then, run the static
binary directly on the host or in a scratch container.

---

## Development

kproxy is written in **Go** and ships as two binaries sharing core packages
under `internal/`. See **[`README.md` developer guide](README.md)** — the full
developer documentation covering the architecture, the wire protocol, the
code layout, testing, and how to extend kproxy.

Quick commands:

```sh
make build    # build both binaries into bin/
make test     # run all unit + integration tests
make race     # tests under the race detector (requires gcc)
make vet      # go vet
```

---

## Status and roadmap

Implemented (Phases 0–1): protocol & multiplexer, HTTP + TCP tunnels, hash /
custom subdomains, custom domains, WebSocket upgrades, reconnection with
backoff, keepalives, TLS via ACME or static certs, admin-key auth, agent
config persistence, JSON logs, CI, full test suite, cross-platform Go build.

Planned: multi-tunnel ergonomics and port pinning (2), real API-key store with
hashing, expiry and limits (3), web dashboard (4), per-tunnel auth and IP
allowlists (5), installers & packaging (6), metrics, load-balancing tunnels,
flow control (7).

See [`docs/roadmap.md`](docs/roadmap.md) for the full phased plan.

---

## License

MIT — use it, fork it, and if you build something great on top of it,
contribute it back.