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
[developer guide](readmedev.md).

---

## Features

### Tunnels
- **HTTP tunnels** — expose web apps, APIs, and static sites:
  `kproxy http 8082`.
- **TCP tunnels** — expose any raw TCP service (SSH, databases, game servers,
  VNC): `kproxy tcp 22`.
- **WebSocket support** — WebSocket and other HTTP upgrade requests
  (`Connection: upgrade`) are tunneled transparently with no extra config.
- **Multiple tunnels** — start many tunnels from one process with a tunnel
  config file: `kproxy tunnels -f tunnels.json`, or run several `kproxy`
  commands side by side (`kproxy http 8082 --subdomain api` and
  `kproxy tcp 3306`).
- **TCP port pinning** — request a specific public port for a TCP tunnel:
  `kproxy tcp 3306 --port 2200` → `tcp://yourdomain.com:2200`.

### Public endpoints
- **Random hash subdomains** by default: `https://7f3a9c21.yourdomain.com`.
- **Custom subdomains**: `kproxy http 8082 --subdomain myapp` →
  `https://myapp.yourdomain.com`.
- **Custom domains**: `kproxy http 8082 --domain app.client.com` — your client
  points their domain at your server and sees the app on their own URL.
- **Custom-domain verification** — when the operator sets `--verify-key`, a
  custom domain is only honored once a DNS TXT record proves you control it
  (see [Domain verification](#domain-verification)).
- **TCP ports** are allocated automatically from a configurable public range
  (default `20000–29999`): `tcp://yourdomain.com:20000`. To keep a fixed port,
  pin it with `--port` (see below).

### Reliability
- **Automatic reconnect** with exponential backoff (1s → 30s) when the network
  blips; tunnels are re-registered transparently.
- **Keepalive pings** on both sides detect and drop half-open connections.
- **Load-balanced tunnels** — several agents may claim the same subdomain; the
  relay distributes traffic across them by least-active-connection and keeps
  serving from the survivors when one disconnects.
- **Graceful tunnel close** — tunnels are released immediately on agent exit
  and when a local app stops accepting connections; the endpoint is freed and
  the tunnel reopens automatically when the app comes back (new public URL for
  random-hash hosts).
- **Graceful shutdown** on `Ctrl+C` / `SIGTERM` for both the agent and server.
- **Flow control** — per-stream send windows prevent a slow consumer from
  stalling other streams over the shared multiplexed connection.

### Security
- **Agent authentication** via per-user API keys, hashed with **argon2id**
  (secrets are 128-bit random and shown exactly once at issuance).
- **Per-key limits** — issue keys with an HTTP request rate cap
  (`--rate`, enforced with a 429), a bandwidth cap (`--bandwidth`, paced
  both directions), and an allowed-subdomain allowlist (`--subdomain`).
- **Per-tunnel protection** — protect a single tunnel with HTTP Basic auth
  (`--basic-auth`), restrict it to IP allow/deny lists (`--ip-allow`,
  `--ip-deny`), and bound request bodies (`--max-request-size` → 413) and
  request duration (`--request-timeout` → 503). Limits are set by the agent
  but enforced by the server, so the relay stays in control.
- **Request IDs** — every proxied request carries an `X-Request-Id` header
  end-to-end and appears in the live request inspector, so a slow request can
  be correlated across client, relay and app logs.
- **Custom-domain verification** — with `--verify-key` the server issues a DNS
  TXT token that proves you control a custom domain before honoring it.
- **Admin API** on its own loopback listener (default `127.0.0.1:55556`) for
  issuing/revoking keys, authenticated with `--admin-key`.
- **HTTPS** on public endpoints via automatic LetsEncrypt certificates
  (ACME) or your own certificates.
- **TLS 1.2+** minimum, **first-run key prompt** that stores your key in a
  per-user config file with restrictive permissions.
- **OS keyring** — `--api-key` and `--admin-key` accept `keyring:NAME` to read
  the secret from the OS keyring (Windows secrets are DPAPI-encrypted) instead
  of leaving it in a config file; `kproxy keyring set|get|rm|list` manages
  entries.
- Local app is only reachable through the tunnel; nothing inbound is exposed
  on the dev machine.

### Operations
- **Web dashboard** — a React admin UI is embedded in the server binary and
  served on the admin listener: live tunnel list, a real-time request
  inspector (host / method / path / status / duration / bytes over SSE), and
  API-key management with per-key limits. Log in with the admin key; it is
  separate from agent API keys.
- **JSON or human-readable logs** (`--json`, `--verbose`).
- **Single static binary** — no runtime dependencies, no installer cruft.
- **Prometheus metrics** — `GET /metrics` on the admin listener exposes
  request/byte counters per tunnel, plus tunnel/agent/uptime/version gauges.
- **Request logs & replay** — every proxied request is logged with redaction
  (path only: query strings, headers and bodies are never captured), and the
  most recent requests are kept in a bounded in-memory ring served by
  `GET /api/v1/requests` and `kproxy requests`.
- **Cross-platform** — Windows, Linux (deb/rpm), macOS; amd64 and arm64.
- **Self-contained** — the only third-party dependency is Google's
  `x/crypto` (ACME client), pinned and vendored at build time.

---

## Requirements

| Component | Requirement |
|---|---|
| **Server** | A machine with a public IP (VPS), ports 80/443 open, and a domain you control with a wildcard `*.domain` A/AAAA record pointing at it. Linux recommended. |
| **Agent** | Any machine with internet access (dev laptop, CI runner). No public IP, no router changes needed. |
| **Build** | Go ≥ 1.24 (only needed to build from source; released binaries need nothing). |

---

## Installation

### From source (any OS)

Requires Go ≥ 1.24. No other toolchain needed — the embedded dashboard ships
pre-built, so a plain `go build` works without node.

```sh
git clone https://github.com/kkennymore/kproxy.git
cd kproxy
make build            # builds bin/kproxy and bin/kproxyd
```

Or install straight into your Go bin directory:

```sh
go install github.com/kkennymore/kproxy/cmd/kproxy github.com/kkennymore/kproxy/cmd/kproxyd
```

The produced binaries (`kproxy`, `kproxyd` — `kproxy.exe`/`kproxyd.exe` on
Windows) are fully static and have no runtime dependencies, so you can copy
them onto any machine of the same OS/arch and run them as-is.

### Prebuilt releases

Every tagged release publishes both binaries for amd64 + arm64:

| Platform | Artifacts |
|---|---|
| Windows | `.zip`, `.msi` (WiX installer) |
| Linux | `.tar.gz`, `.deb` (Debian/Ubuntu), `.rpm` (Fedora/RHEL) |
| macOS | `.zip` |

Every archive contains `kproxy` + `kproxyd` + `checksums.txt`. See the
[releases page](https://github.com/kkennymore/kproxy/releases) for the latest.

### Linux

#### Debian / Ubuntu (deb)

```sh
sudo apt update
sudo apt install -y ./kproxy_<version>_linux_amd64.deb
# installs kproxyd to /usr/bin + a hardened systemd unit, then starts it
```

The post-install script installs and starts the systemd service. Configure it
via `/etc/kproxy/kproxyd.env`, then `sudo systemctl restart kproxyd`.

#### Fedora / RHEL (rpm)

```sh
sudo dnf install -y ./kproxy_<version>_linux_amd64.rpm
sudo systemctl enable --now kproxyd
```

If you built from source instead:

```sh
sudo cp bin/kproxy bin/kproxyd /usr/local/bin/
```

Open the ports the server needs:

```sh
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --permanent --add-port=55555/tcp      # agent control
sudo firewall-cmd --permanent --add-port=20000-29999/tcp  # TCP tunnels
sudo firewall-cmd --reload
```

Install and start it as a service:

```sh
sudo mkdir -p /etc/kproxy
sudo tee /etc/kproxy/kproxyd.env >/dev/null <<'EOF'
KPROXY_DOMAIN=yourdomain.com
KPROXY_ACME_EMAIL=you@example.com
KPROXY_ADMIN_KEY=choose-a-strong-secret
EOF
sudo curl -fsSL https://raw.githubusercontent.com/kkennymore/kproxy/main/packaging/kproxyd.service \
  -o /usr/lib/systemd/system/kproxyd.service
sudo systemctl daemon-reload
sudo systemctl enable --now kproxyd
journalctl -u kproxyd -f
```

The unit runs `kproxyd` as a dynamic user with strict hardening
(`NoNewPrivileges`, `ProtectSystem=strict`, `CAP_NET_BIND_SERVICE` for
:80/:443) and stores state in `/var/lib/kproxy`. If it fails to start, check
SELinux with `ausearch -m avc -ts recent`.

#### Any other Linux (tar.gz)

```sh
tar -xzf kproxy_<version>_linux_amd64.tar.gz
sudo install -m 0755 kproxyd kproxy /usr/local/bin/
```

### Windows

#### MSI installer

```powershell
# double-click kproxy_<version>_windows_amd64.msi, or install silently:
Start-Process msiexec -ArgumentList '/i','kproxy_<version>_windows_amd64.msi','/qn' -Wait
```

Installs both binaries to `%ProgramFiles%\kproxy\`. Add them to `PATH` or call
them by full path:

```powershell
& "$env:ProgramFiles\kproxy\kproxy.exe" --version
```

#### Zip (portable)

```powershell
Expand-Archive kproxy_<version>_windows_amd64.zip -DestinationPath $env:LOCALAPPDATA\kproxy
$env:PATH += ";$env:LOCALAPPDATA\kproxy"
kproxy.exe --version
```

Firewall: the **agent** only makes outbound connections, so nothing to open.
The **server** needs inbound rules for the public ports
(`netsh advfirewall firewall add rule ...` for 80/443, `55555`, and the TCP
tunnel range) if you host a relay on Windows.

### macOS

```sh
tar -xzf kproxy_<version>_darwin_arm64.tar.gz   # or _amd64 for Intel
sudo install -m 0755 kproxyd kproxy /usr/local/bin/
```

Or install via Go:

```sh
go install github.com/kkennymore/kproxy/cmd/kproxy github.com/kkennymore/kproxy/cmd/kproxyd
```

If Gatekeeper blocks an unsigned prebuilt binary, right-click it in Finder →
**Open**, or remove the quarantine attribute once:

```sh
xattr -d com.apple.quarantine kproxy kproxyd
```

### Docker

A multi-arch image is built from `packaging/Dockerfile` (see
[Deployment](#deployment) for the full command):

```sh
docker run -d --name kproxyd --restart unless-stopped \
  -p 80:80 -p 443:443 -p 55555:55555 \
  -v kproxyd-data:/var/lib/kproxy \
  kproxyd:latest \
  --domain yourdomain.com --acme-email you@example.com --admin-key "choose-a-strong-secret"
```

The **usage is identical on every OS** — the same `kproxyd` flags, `kproxy`
commands, config file and keyring behavior (Windows uses DPAPI-encrypted
secrets; macOS/Linux use an owner-only file). On Windows the binaries are
`kproxy.exe`/`kproxyd.exe`; the examples below use the Unix names.

---

## Quick start

### 1. Start the server (on your VPS)

```sh
kproxyd \
  --domain yourdomain.com \
  --http-addr :80 \
  --https-addr :443 \
  --acme-email you@example.com \
  --admin-key "choose-a-strong-admin-secret" \
  --data-dir /var/lib/kproxy
```

What this does:
- Listens for agent connections on the control port (`:55555` by default).
- Serves public HTTPS on `:443` (automatic LetsEncrypt certs via `--acme-email`)
  and redirects `:80` to HTTPS.
- Runs the admin API on `127.0.0.1:55556` (loopback) so operators can issue
  API keys with `--admin-key`.

> **No domain yet?** You can run in dev mode without HTTPS:
> `kproxyd --domain localhost --http-addr :8080 --https-addr "" --admin-key test`

### 2. Issue an API key (once)

```sh
kproxy key create --name my-laptop --ttl 30d --admin-key "choose-a-strong-admin-secret"
# Created key:
#   ID:      k_9f3a2c11
#   Name:    my-laptop
#   Expires: 2026-09-18T12:00:00+02:00
#   Secret:  kproxy_2f8c...   ← shown only once, save it
```

The server stores only the argon2id hash of the secret; the plaintext secret
is returned exactly once. Without an API key the server refuses agents.

### 3. Start the agent (on your dev machine)

```sh
kproxy http 8082 --server http://your-vps:55555 --api-key "kproxy_2f8c..."
```

If you omit `--api-key`, kproxy prompts for one on first run and stores it in
your config file so future runs need no arguments:

```sh
kproxy http 8082 --server http://your-vps:55555
```

### 4. Share the URL

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
kproxy tunnels -f FILE [flags] expose several tunnels from one process
kproxy key <cmd> [flags]       manage api keys on the relay
kproxy requests [flags]        show recent proxied requests from the relay log
```

| Flag | Default | Description |
|---|---|---|
| `--subdomain NAME` | random | Request a specific subdomain (`myapp` → `myapp.domain`) |
| `--domain HOST` | — | Expose on a custom domain you control (`app.client.com`) |
| `--local-host HOST` | `127.0.0.1` | Local host/interface to forward to |
| `--port PORT` | auto | Request a specific public TCP port (`tcp` tunnels only) |
| `--basic-auth user:pass` | — | Protect the tunnel with HTTP Basic auth (`http` only) |
| `--ip-allow CIDR` | any | Comma-separated IP/CIDR allowlist for public clients (`http`/`tcp`) |
| `--ip-deny CIDR` | — | Comma-separated IP/CIDR denylist; deny wins over allow (`http`/`tcp`) |
| `--max-request-size SIZE` | unlimited | Cap request bodies, e.g. `1mb`; oversized requests get `413` (`http` only) |
| `--request-timeout DURATION` | none | Bound request duration, e.g. `30s`; timed-out requests get `503` (`http` only) |
| `--server URL` | `http://localhost:55555` | Relay server endpoint (`http://` or `https://`) |
| `--api-key KEY` | — | API key for the relay (prompted on first run if absent); use `keyring:NAME` to read it from the OS keyring |
| `--config PATH` | platform default | Config file to read/write instead of the default |
| `--verbose` | off | Debug-level logging |
| `--json` | off | JSON log output instead of human-readable |

Environment variables (used when the flag is not set): `KPROXY_SERVER`,
`KPROXY_API_KEY`.

`kproxy tunnels` takes a `-f FILE` tunnel config file (see
[Configuration](#configuration)) and opens every tunnel in it from one agent
process. It shares the credential precedence of the other commands; the file
may also carry its own `server_url`/`api_key` as fallbacks.

#### Managing API keys

```
kproxy key create [--name NAME] [--ttl DURATION] [--rate N] [--bandwidth SIZE] [--subdomain a,b] --admin-url URL --admin-key SECRET
kproxy key revoke <ID>         --admin-url URL --admin-key SECRET
kproxy key list                --admin-url URL --admin-key SECRET
```

| Flag | Default | Description |
|---|---|---|
| `--admin-url` | `http://127.0.0.1:55556` | Admin API endpoint (the server's loopback admin listener) |
| `--admin-key` | env `KPROXY_ADMIN_KEY` | Admin secret that authenticates the request; use `keyring:NAME` to read it from the OS keyring |
| `--name` | — | Human label for a new key |
| `--ttl` | never | Key lifetime: `24h`, `7d`, `30d`, … |
| `--rate` | 0 (unlimited) | Max HTTP requests per second; excess requests get `429` |
| `--bandwidth` | 0 (unlimited) | Max tunnel throughput, e.g. `1mb`, `512kb`, `2.5gb` (paced both directions) |
| `--subdomain` | any | Comma-separated allowlist of subdomains/domains this key may claim |

Revoking a key takes effect immediately: connected agents keep their current
tunnels until they disconnect, and any reconnect is refused with
`api key revoked`.

#### Managing secrets in the OS keyring

```
kproxy keyring set NAME [VALUE]   store a secret (reads stdin if VALUE omitted)
kproxy keyring get NAME           print a stored secret
kproxy keyring rm NAME            remove a stored secret
kproxy keyring list               list stored names
```

Windows secrets are encrypted with DPAPI (local-machine scope) before being
written to `%AppData%\kproxy\keyring.json`; macOS/Linux use an owner-only
(0600) file under the user config directory. Reference an entry anywhere a
secret is accepted, e.g. `--api-key keyring:my-laptop` or
`--admin-key keyring:relay-admin` (also works via the `KPROXY_ADMIN_KEY`
environment variable and on `kproxyd --admin-key`).

Global commands: `kproxy --version`, `kproxy help`.

#### Managing custom domains

```
kproxy domain verify-token <host>  --admin-url URL --admin-key SECRET
```

Prints the DNS TXT record to publish to prove you control `<host>` (see
[Domain verification](#domain-verification)).

#### Replaying recent requests

```
kproxy requests [--limit N]  --admin-url URL --admin-key SECRET
```

Prints the most recent proxied requests (newest first) from the relay's
bounded in-memory replay log, e.g.:

```sh
kproxy requests --limit 10 --admin-key "operator-secret"
# TIME                   METHOD HOST                     STATUS DURATION  BYTES PATH
# 2026-08-19 10:42:07    GET    api.yourdomain.com           200    12ms  1024 /v1/users
# 2026-08-19 10:41:58    POST   api.yourdomain.com           201   305ms 15360 /v1/orders
```

Only the URL **path** is recorded — query strings, headers and bodies are
redacted, so secrets in URLs or requests never reach the log or the API. The
same data is served by `GET /api/v1/requests` (admin Bearer auth, `?limit=`
up to 1000). Retention is bounded by the server's `--request-log` size.

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
| `--admin-key` | *(empty)* | Secret for the admin API and dashboard (`kproxy key ...`); empty disables the admin API |
| `--admin-addr` | `127.0.0.1:55556` | Admin API + web dashboard listener; set `""` to disable |
| `--tcp-port-range` | `20000-29999` | Public port range allocated to TCP tunnels |
| `--acme-email` | — | Email for LetsEncrypt; enables automatic certificates |
| `--tls-cert` / `--tls-key` | — | Paths to your own certificate and private key |
| `--verify-key` | — | Secret enabling custom-domain verification; when set, custom domains are only honored after their DNS TXT record matches |
| `--request-log` | `1000` | Number of recent proxied requests kept for replay via `/api/v1/requests` (`0` disables) |
| `--data-dir` | `./data` | Directory for the certificate cache, key store (`keys.json`) and runtime state |
| `--verbose` | off | Debug-level logging |
| `--json` | off | JSON log output |
| `--version` | — | Print version and exit |

> `--admin-key` accepts a `keyring:NAME` reference so the secret can live in
> the OS keyring instead of an env file (see [Managing secrets in the OS
> keyring](#managing-secrets-in-the-os-keyring)).

> Exactly one of `--acme-email` or `--tls-cert/--tls-key` is required when
> `--https-addr` is enabled.

### Prometheus metrics

With the admin API enabled (`--admin-addr` + `--admin-key`), the admin
listener also serves Prometheus metrics at `/metrics`, authenticated with the
same admin key as a Bearer token (also accepted as `?token=`), e.g.:

```sh
curl -H "Authorization: Bearer $KPROXY_ADMIN_KEY" http://127.0.0.1:55556/metrics
```

```
kproxy_requests_total{tunnel="myapp.kproxy.test",proto="http"}  42
kproxy_tunnel_bytes_total{tunnel="myapp.kproxy.test",proto="http"}  1048576
kproxy_tunnels{proto="http"}  3
kproxy_agents  2
kproxy_uptime_seconds  86400
kproxy_version_info{version="0.1.0"}  1
```

Counters are cumulative per tunnel (and protocol); gauge values are derived
when the endpoint is scraped. In a Prometheus config, set `bearer_token` (or
`bearer_token_file`) to the admin key for this job.

### Web dashboard

The admin listener serves both the control API (`/api/v1/...`) and an embedded
web dashboard. Point a browser at it and log in with `--admin-key`:

```sh
open http://127.0.0.1:55556          # or port-forward / SSH -L to your VPS
```

The dashboard shows:

- **Tunnels** — every live tunnel with its public URL, protocol, local target,
  agent ID, opened time, request count and traffic so far.
- **Live requests** — each proxied request streams in as it happens (host,
  method, path, status, duration, response bytes).
- **API keys** — create keys with `--name`/`--ttl`/`--rate`/`--bandwidth`/
  `--subdomain` limits, reveal the one-time secret, and revoke keys.

The dashboard is a React + Vite app embedded into the server binary at build
time; the operator does not need Node.js installed. Rebuild it with
`make web` when changing `web/`.

> The dashboard and the admin CLI are just two clients of the same versioned
> control API — anything the UI does, `kproxy key ...` can do too.

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

Your client adds `app.client.com` → your server IP (and, when the relay runs
with `--verify-key`, publishes the TXT record from
`kproxy domain verify-token app.client.com`), then:

```sh
kproxy http 3000 --domain app.client.com --server https://relay.example.com:55555
# → https://app.client.com
```

### Protect a tunnel with basic auth / IP allowlist / size & time limits

```sh
kproxy http 3000 \
  --basic-auth alice:s3cret \
  --ip-allow 203.0.113.0/24,198.51.100.7 \
  --max-request-size 1mb \
  --request-timeout 30s
# Everyone else sees 401; bodies over 1mb get 413; requests over 30s get 503.
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

### Keep a fixed public port (port pinning)

```sh
kproxy tcp 3306 --port 2200 --server https://relay.example.com:55555
# → tcp://relay.example.com:2200   (fails if 2200 is already taken)
```

### WebSockets over HTTP tunnel

No special flag — a WebSocket app on your local server just works:

```sh
kproxy http 8080 --subdomain live --server https://relay.example.com:55555
# connect client-side to wss://live.relay.example.com
```

### Multiple tunnels from one agent

Define them all in a tunnel file and start one process:

```sh
$ cat tunnels.json
{
  "tunnels": [
    {"proto": "http", "local": "8082", "subdomain": "api"},
    {"proto": "http", "local": "3000"},
    {"proto": "tcp",  "local": "127.0.0.1:3306", "port": 2200}
  ]
}

$ kproxy tunnels -f tunnels.json --server https://relay.example.com:55555
Tunnel online on relay.example.com
  https://api.relay.example.com
  https://8f2ac1d4.relay.example.com
  tcp://relay.example.com:2200
```

Running several commands in parallel also works:

```sh
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
config file → tunnel file (`server_url`/`api_key`) → default / interactive
prompt.

### Tunnel config file

`kproxy tunnels -f FILE` reads a JSON file describing one or more tunnels:

```json
{
  "server_url": "https://relay.example.com:55555",
  "api_key": "your-secret-key",
  "tunnels": [
    {"proto": "http", "local": "8082", "subdomain": "api"},
    {"proto": "http", "local": "127.0.0.1:3000"},
    {"proto": "tcp",  "local": "3306", "port": 2200},
    {"proto": "http", "local": "9090", "domain": "app.client.com"}
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `server_url` | no | Relay server; falls back to flag/env/config/default |
| `api_key` | no | API key; falls back to flag/env/config, else prompts |
| `proto` | yes | `http` or `tcp` |
| `local` | yes | Local target. A bare port number means `127.0.0.1:<port>` |
| `port` | no | Fixed public TCP port (`tcp` only; auto-allocated if omitted) |
| `subdomain` | no | Requested subdomain (HTTP only) |
| `domain` | no | Custom domain (HTTP only) |
| `basic_auth` | no | `user:pass` HTTP Basic auth for the tunnel (HTTP only) |
| `ip_allow` | no | IP/CIDR allowlist (HTTP/TCP); empty admits everyone not denied |
| `ip_deny` | no | IP/CIDR denylist (HTTP/TCP); deny wins over allow |
| `max_request_size` | no | Request body cap, e.g. `1mb` (HTTP only); oversized → `413` |
| `request_timeout` | no | Request duration bound, e.g. `30s` (HTTP only); timed out → `503` |

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
kproxyd --domain localhost --http-addr :8080 --https-addr "" --admin-key test --data-dir ./data
kproxy key create --name dev --admin-key test        # once; prints a kproxy_ secret
kproxy http 8082 --server http://localhost:55555 --api-key kproxy_...
```

Public URLs look like `http://7f3a9c21.localhost:8080`. To test from a browser
locally, add a hosts-file entry (or use a domain that resolves to 127.0.0.1)
so `*.yourdomain` reaches your machine.

---

## Domain verification

By default **any** key can claim any custom domain (subject to the key's
`--subdomain` allowlist). If you run a shared relay, set `--verify-key` on the
server so a custom domain is only honored once the requester proves they own
it:

```sh
kproxyd --domain yourdomain.com ... --verify-key "a-secret-known-only-to-the-operator"
```

1. The operator fetches the token for the domain the client wants to use:

   ```sh
   kproxy domain verify-token app.client.com --admin-key "operator-secret"
   # publish TXT  _kproxy.app.client.com  "kproxy-verify-1a2b3c4d"
   ```

2. The domain owner adds that TXT record at `_kproxy.app.client.com`.
3. When an agent requests `--domain app.client.com`, the server checks the TXT
   record; matching tokens are cached and the domain is honored.

Domains without a matching record are refused with the exact value to publish,
so the requester can fix their DNS and retry. Verification only applies to
custom domains; hash and custom subdomains are unaffected. Tokens are derived
from the domain and `--verify-key`, so `verify-token` needs no network round
trip and always returns the same value for a given domain.

---

## Security model

| Concern | Approach |
|---|---|---|
| Agent authentication | Per-user API keys; secrets hashed with argon2id, plaintext shown once at issuance. |
| Key storage | `keys.json` in `--data-dir` (`0600`): argon2id hashes + sha256 lookup fingerprints; secrets are never stored. |
| Admin access | Loopback-only admin API (`127.0.0.1:55556` by default) guarded by `--admin-key`. |
| Abuse limiting | Per-key request rate (429), bandwidth pacing (both directions), and allowed-subdomain allowlists. |
| Per-tunnel protection | HTTP Basic auth, IP allow/deny lists, request body caps (413) and request timeouts (503), all enforced server-side. |
| Custom-domain control | DNS TXT verification (`--verify-key`) proves a domain owner before a custom domain is honored. |
| Public endpoints | HTTPS with auto-rotating LetsEncrypt certs or your own certs. |
| Transport | Control connections optionally TLS; tunnel traffic rides that encrypted channel. |
| TLS version | Minimum TLS 1.2. |
| Local exposure | The agent dials the local service; nothing is ever exposed inbound on the dev machine. |
| Server hardening | Firewall the control port (`:55555`) to only your agents; keep `--admin-key` strong; bind `--admin-addr` to loopback. |

Keys with no limits configured are effectively unlimited except for expiry
and revocation. Do not run the server without an admin key or with the admin
API on a public interface.

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

A multi-arch Docker image is built from `packaging/Dockerfile`:

```sh
make docker                          # docker build -t kproxyd:latest .
docker run -d --name kproxyd --restart unless-stopped \
  -p 80:80 -p 443:443 -p 55555:55555 \
  -v kproxyd-data:/var/lib/kproxy \
  kproxyd:latest \
  --domain yourdomain.com --acme-email you@example.com --admin-key "choose-a-strong-secret"
```

The image runs as a non-root user with CA certificates and the data directory
on a volume; pass the same flags as the bare binary.

### One-command bootstrap (Linux + systemd)

The quickest way to stand up a server on a fresh VPS:

```sh
curl -fsSL https://raw.githubusercontent.com/kkennymore/kproxy/main/packaging/install-kproxyd.sh | sudo sh
```

This downloads the latest release, installs `kproxy`/`kproxyd` to
`/usr/local/bin`, writes a config template to `/etc/kproxy/kproxyd.env`,
installs a hardened systemd unit (with `CAP_NET_BIND_SERVICE` for ports
80/443) and starts the service. Edit `/etc/kproxy/kproxyd.env`, then
`systemctl restart kproxyd`.

The packaged `.deb`/`.rpm` do the same for package-managed systems.

---

## Development

kproxy is written in **Go** and ships as two binaries sharing core packages
under `internal/`. See **[`readmedev.md` developer guide](readmedev.md)** — the
full developer documentation covering the architecture, the wire protocol, the
code layout, testing, and how to extend kproxy.

Quick commands:

```sh
make build    # build both binaries into bin/ (rebuilds the embedded dashboard)
make web      # rebuild the embedded dashboard from web/ (requires node/npm)
make dist     # build all release artifacts locally via GoReleaser (needs goreleaser)
make docker   # build the kproxyd Docker image (needs docker)
make test     # run all unit + integration tests
make race     # tests under the race detector (requires gcc)
make vet      # go vet
```

---

## Status and roadmap

Implemented (Phases 0–8): protocol & multiplexer, HTTP + TCP tunnels,
hash / custom subdomains, custom domains, TCP port pinning, multi-tunnel
config files, WebSocket upgrades, reconnection with backoff, keepalives,
graceful tunnel close + auto-recovery on local-app failure, per-user API keys
(argon2id hashes, expiry, revocation, admin API) with per-key rate,
bandwidth and allowed-subdomain limits, per-tunnel basic auth, IP
allow/deny lists, request body caps and timeouts, request IDs, DNS TXT
custom-domain verification, versioned control API (`/api/v1/...`), live
tunnel list + real-time request inspector + key CRUD in an embedded web
dashboard, TLS via ACME or static certs, agent config persistence, JSON
logs, CI, full test suite, cross-platform build, packaging (GoReleaser
archives + deb/rpm + Windows MSI, systemd unit, Docker image, one-command
bootstrap script), Prometheus metrics, load-balanced tunnels, per-stream flow
control, OS-keyring secret storage, fuzzing of the frame parser and control
codec, and structured request logs with bounded redacted replay
(`/api/v1/requests`, `kproxy requests`).

See [`docs/roadmap.md`](docs/roadmap.md) for the full phased plan.

---

## License

MIT — use it, fork it, and if you build something great on top of it,
contribute it back.