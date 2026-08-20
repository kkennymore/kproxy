# kproxy — Developer Guide

Everything you need to develop, extend, test and debug kproxy: the technology
choices, the inner workings, the wire protocol, the concurrency model, and the
conventions to follow when contributing.

For end-user documentation see **[README.md](README.md)**.

---

## Table of contents

- [1. Technology choices](#1-technology-choices)
- [2. System architecture](#2-system-architecture)
- [3. Repository layout](#3-repository-layout)
- [4. The wire protocol](#4-the-wire-protocol)
- [5. Data flow walkthroughs](#5-data-flow-walkthroughs)
- [6. Concurrency model](#6-concurrency-model)
- [7. Configuration & platform details](#7-configuration--platform-details)
- [8. Security internals](#8-security-internals)
- [9. Testing](#9-testing)
- [10. Building & tooling](#10-building--tooling)
- [11. How to extend kproxy](#11-how-to-extend-kproxy)
- [12. Status & roadmap](#12-status--roadmap)
- [13. Coding conventions](#13-coding-conventions)

---

## 1. Technology choices

### Why Go?

kproxy is built in **Go** (module `kproxy`, go directive `1.24`), and every
decision behind that choice maps directly onto the project's requirements:

| Requirement | How Go satisfies it |
|---|---|
| **Self-contained** | Static binaries with zero runtime dependencies. No VM, no interpreter, no shared libraries. The only third-party module is Google's `golang.org/x/crypto` (ACME client), pinned in `go.mod`. |
| **Cross-platform** | One codebase compiles for Windows, Linux and macOS on amd64 and arm64 via `GOOS`/`GOARCH`. File paths, config dirs and signals are handled with the platform APIs in the standard library. |
| **Concurrency** | Goroutines and channels are the natural model for multiplexing thousands of connections over one tunnel. The `net/http` stack and `io.Copy` bridges need almost no custom plumbing. |
| **Speed & resources** | A single goroutine per connection with zero-copy-ish `io.Copy` transfers; memory is bounded by per-stream buffers and frame-size caps. The whole agent binary is ~7 MB. |
| **Security** | `crypto/tls` (TLS 1.2+), constant-time compare habits, `crypto/rand` for token generation, and a minimal attack surface. |
| **Maintainability** | The standard library covers HTTP/2, TLS, JSON, logging (`log/slog`), flags, signals and embedding. Fewer dependencies means fewer upgrade risks. |

### Dependency policy

- **Standard library first.** Everything in `internal/` uses the stdlib except
  the single `golang.org/x/crypto` import in `cmd/kproxyd`.
- **No runtime package installation.** Dependencies are compile-time only and
  are vendored into the module (`go mod vendor`), so building on a fresh
  machine needs nothing but the Go toolchain.
- **Go 1.24+ minimum.** Modern stdlib features such as pattern-based
  `ServeMux` routing, `log/slog`,
  `atomic.Int64`, and `errors.Is` are used throughout. Keep using modern stdlib
  features rather than pulling in libraries.

---

## 2. System architecture

```
+----------+   public HTTPS/TCP   +--------------------------+
|  client  | -------------------> |          kproxyd         |
+----------+    :443 / :80 / :port |  relay registry          |
                                   |  HTTP/TCP routers        |
                                   |  control API (handshake)  |
                                   +------------+-------------+
                                                |  ONE persistent connection
                                                |  (multiplexed streams)
                                   +------------+-------------+
                                   |          kproxy          |
                                   |  (agent)                 |
                                   |  stream acceptor + bridge |
                                   +------------+-------------+
                                                |
                                    local dial (127.0.0.1:8082)
                                                |
                                          your app / service
```

Two binaries, one shared core:

- **`cmd/kproxyd`** — the relay server. Owns the public endpoints, terminates
  TLS, authenticates agents, and routes client traffic over the correct
  agent's tunnel.
- **`cmd/kproxy`** — the agent CLI. Connects outbound to the server, requests
  tunnels, and bridges tunneled streams to local services.

The design principle that keeps it simple: **the agent is a pure byte bridge
with no HTTP awareness.** The server does all HTTP parsing; the agent just
copies bytes between a multiplexed stream and a local TCP connection. This is
why HTTP and TCP tunnels share one code path (`protocol.Bridge`).

---

## 3. Repository layout

```
.
├── cmd/
│   ├── kproxy/                 agent CLI (subcommands, flags, first-run prompt)
│   └── kproxyd/                relay daemon (listeners, TLS/ACME, admin API)
├── internal/
│   ├── admin/                  admin HTTP API client (the CLI uses /api/v1)
│   ├── agent/                  agent control loop, reconnect/backoff, accept loop
│   ├── auth/                   argon2id hashing + secret generation
│   ├── config/                 agent config file persistence
│   ├── keyring/                OS-keyring secret store (Windows DPAPI, 0600 file elsewhere)
│   ├── metrics/                stdlib Prometheus registry (labeled counters/gauges)
│   ├── protocol/               wire framing, stream multiplexer, control msgs
│   ├── ratelimit/              stdlib token buckets (rate / bandwidth pacing)
│   ├── relay/                  server registry, host/port allocation, routing, events, request log
│   ├── server/                 control-plane API + embedded dashboard (go:embed)
│   ├── store/                  JSON-file-backed api key store
│   ├── units/                  size / duration parsing shared by admin + relay
│   └── version/                version/commit injection
├── web/                        React + Vite dashboard source (built into internal/server/dashboard)
├── examples/demo/              tiny web app for manual smoke tests
├── packaging/                  Dockerfile, systemd unit, MSI wxs + builder, bootstrap script
├── docs/
│   ├── architecture.md         high-level design & deployment notes
│   └── roadmap.md              phased plan
├── .github/workflows/ci.yml    CI matrix (vet + race test + build, 3 OSes) + installer smoke
├── .github/workflows/release.yml  GoReleaser release on tags + MSI build/upload
├── .goreleaser.yaml            release pipeline (builds, archives, deb/rpm)
├── Makefile                    build/test/vet/race/dist/docker targets
├── go.mod / go.sum             module definition
├── LICENSE                     MIT
└── README.md                   end-user documentation
```

| Package | Responsibility | Key types |
|---|---|---|
| `protocol` | Wire format, multiplexing, byte bridge | `Mux`, `Stream`, `FrameType`, `Hello`/`Welcome`/`ErrorMsg` |
| `relay` | Server-side tunnel bookkeeping, routing, load balancing and events | `Server`, `client`, `tunnel`, `tunnelSet`, `KeyValidator`, `Event`/`TunnelInfo`/`RequestInfo` |
| `agent` | Client-side lifecycle and bridging | `Agent` |
| `auth` | Argon2id hashing and secret generation | — |
| `store` | Api key persistence and validation | `Store`, `KeyInfo`, `KeyIdentity`, `Limits` |
| `ratelimit` | Token-bucket rate/bandwidth limits | `Bucket` |
| `admin` | Admin HTTP API client used by the CLI | `CreateKey`, `ListKeys`, `RevokeKey`, `ListRequests` |
| `server` | Versioned control API + SSE + embedded dashboard | `NewHandler`, `handleStream`, `handleRequests` |
| `config` | Config file read/write | `AgentConfig` |
| `keyring` | OS-keyring secrets (`keyring:NAME` refs) | `Ring`, `Resolve` |
| `metrics` | Prometheus text-format registry | `Registry`, `Counter`, `Gauge` |
| `units` | Size/duration parsing (`ParseSize`, `ParseTTL`) | — |

---

## 4. The wire protocol

The protocol is a **single persistent connection carrying many multiplexed
streams** plus out-of-band control frames. It lives in `internal/protocol`.

### Frame format

Every frame on the wire:

```
+----------------+--------+------------------+---------------------------+
| payload length | type   | stream id        | payload                   |
| 4 bytes BE     | 1 byte | 8 bytes BE       | length bytes              |
+----------------+--------+------------------+---------------------------+
```

Header is 13 bytes, big-endian. `maxFrameSize` (16 MiB) bounds any single
payload so a misbehaving peer cannot exhaust memory.

### Frame types

| Type | Value | Direction | Payload |
|---|---|---|---|
| `FrameData` | 1 | both | raw bytes for a stream |
| `FrameOpen` | 2 | relay→agent | the target tunnel id (JSON-free, plain string) |
| `FrameClose` | 3 | both | (none) — peer closed the stream |
| `FrameControl` | 4 | both | JSON control message |
| `FramePing` | 5 | both | (none) — keepalive probe |
| `FramePong` | 6 | both | (none) — reply, updates `lastPong` |
| `FrameWindow` | 7 | both | 8-byte big-endian byte count — credit granted on a stream |

### Control messages (JSON)

Control frames flow over stream id 0 and carry one of these payloads:

**`hello`** (agent → server, first message):

```json
{
  "type": "hello",
  "version": "0.1.0",
  "api_key": "secret",
  "tunnels": [
    {"id": "main", "proto": "http", "local": "127.0.0.1:8082", "subdomain": "api", "domain": ""},
    {"id": "db", "proto": "tcp", "local": "127.0.0.1:3306", "port": 2200}
  ]
}
```

`TunnelSpec` fields (see `internal/protocol/control.go`): `id`, `proto`
(`http`/`tcp`), `local`, `subdomain`, `domain`, `port` (a fixed public TCP
port; `0`/omitted means auto-allocate from the range), and the Phase 5
security options — `basic_auth` (`user:pass`), `ip_allow`/`ip_deny` (IP/CIDR
lists), `max_request_size` (e.g. `1mb`), `request_timeout` (e.g. `30s`). The
relay re-parses and validates these server-side in `applySpecOptions`; the
agent never gets to enforce them.

**`welcome`** (server → agent, success reply):

```json
{
  "type": "welcome",
  "version": "0.1.0",
  "server": "example.com",
  "tunnels": [{"id": "main", "public_url": "https://7f3a9c21.example.com"}]
}
```

**`error`** (server → agent, fatal handshake failure or post-registration
rejection):

```json
{"type": "error", "message": "invalid api key"}
```

**`close`** (agent → server, graceful tunnel teardown):

```json
{"type": "close", "tunnels": ["main", "db"]}
```

The server unregisters the listed tunnels immediately, freeing their hosts and
TCP listeners. Unknown IDs are ignored. Sent on agent exit and when a local
target goes down.

**`add`** (agent → server, open more tunnels after registration):

```json
{"type": "add", "tunnels": [{"id": "db", "proto": "tcp", "local": "127.0.0.1:3306", "port": 2200}]}
```

Used to reopen a tunnel whose local target recovered. The server replies with:

**`assigned`** (server → agent, reply to `add`):

```json
{"type": "assigned", "tunnels": [{"id": "db", "public_url": "tcp://example.com:2200"}]}
```

The `type` field disambiguates; the wire types are defined in
`internal/protocol/control.go` (`TypeHello`, `TypeWelcome`, `TypeClose`,
`TypeAdd`, `TypeAssigned`, `TypeError`, `ProtoHTTP`, `ProtoTCP`).

### Stream lifecycle

1. **Open:** the server allocates an id via `Mux.Open(tunnelID)`, registers the
   local `Stream`, and sends a `FrameOpen`. The agent's read loop creates its
   counterpart and pushes it onto the accept queue; its `Meta()` is the tunnel
   id used to find the local target.
2. **Data:** each side writes `FrameData` frames tagged with the stream id. The
   receiver appends payloads to a per-stream byte buffer (`buf`, capped at
   `streamBufMax` = 2× the send window); the consumer reads them through the
   `net.Conn` adapter.
3. **Window:** each stream has a 256 KiB send window (`streamWindowSize`).
   `Write` blocks once the peer's unacked bytes reach the window and waits on
   `winCond` for credit; the reader grants `FrameWindow` credit via `maybeGrant`
   every time it drains half the window (`streamWindowHalf`), so a slow
   consumer only blocks its own stream's writer, never the mux read loop or
   other streams.
4. **Close:** either side sends `FrameClose`; the peer's reader observes EOF
   once buffered data drains. A stream is evicted from the map only after both
   sides have closed (this guarantees no data is lost in flight).
5. **Teardown:** `Mux.Close()` force-terminates every live stream and closes
   the underlying connection.

### The `net.Conn` adapter

`protocol.Stream` implements `net.Conn`. This is what lets both the agent and
the server use plain `io.Copy`/`net/http` against streams as if they were real
sockets:

- `Read` drains the per-stream byte buffer; returns `io.EOF` after the peer
  closes and buffered data is exhausted, granting window credit as it goes.
- `Write` consumes send-window credit and blocks until the peer grants more.
- `SetDeadline*` are no-ops (deadlines are managed at the mux/HTTP layer).

### Keepalive / liveness

- The agent sends a `Ping` every 30 s and expects a `Pong` within 5 s
  (`Mux.Ping`).
- The server also pings every 30 s and additionally drops any client with no
  frames for 90 s (`keepAliveDead`).
- A failed ping closes the mux, which triggers the agent's reconnect path.

### Flow control

Backpressure is **per-stream** via explicit send windows (`FrameWindow`).
Each stream starts with a 256 KiB window (`streamWindowSize`); a `Write`
sends up to the available credit and blocks (`winCond`) until the peer grants
more. The receiver's byte buffer is capped at `streamBufMax` (2× the window)
and grants `FrameWindow` credit in `streamWindowHalf` increments as the
consumer drains it. A slow consumer therefore stalls only its own writer —
other streams on the same tunnel keep flowing — and a peer that over-sends is
backed up at its `Write` (its send-window credit) rather than at the mux read
loop. Both ends ship in one release, so the protocol needs no version
negotiation for this.

---

## 5. Data flow walkthroughs

### Registration (handshake)

```
agent                     server
  |  connect + FrameControl(hello)   |
  |--------------------------------->|
  |                                  | validate api_key (against admin key)
  |                                  | allocate hosts / tcp ports
  |                                  | bind tcp listeners
  |        FrameControl(welcome)     |
  |<---------------------------------|
  | print public URLs                |
```

The server rejects with `FrameControl(error)` and closes if the key is wrong,
the hello is malformed, a requested subdomain/domain is already in use, or the
TCP port range is exhausted.

### An HTTP request

1. Client → server: `GET https://7f3a9c21.example.com/foo`.
2. `relay.serveHTTP` strips the port from the `Host` header and looks up the
   virtual host in the registry (exact match; unknown hosts get a 404, the
   base domain gets a landing page, `/healthz` returns JSON status). HTTP
   tunnels are grouped in a `tunnelSet`; `serveHTTP` picks one tunnel with
   `tunnelSet.pick()` (least active connections, round-robin on ties), so
   several agents may serve the same subdomain.
3. The server calls `client.openStream(tunnelID)` → sends `FrameOpen` and gets
   a `Stream`.
4. The server serializes the incoming request onto the stream with
   `r.Write(stream)` (handles body, content-length/chunked, trailers).
5. The agent's accept loop dials `127.0.0.1:8082` and bridges bytes, so the
   request bytes reach the app exactly as written.
6. The app's raw response travels back; the server reads it with
   `http.ReadResponse` and writes status, headers and body to the client.

The picked tunnel is also used for the IP/auth/rate checks, so agents sharing
a subdomain should configure identical tunnel options.

### A WebSocket / upgrade request

Upgrade requests (any `Connection: upgrade`) take a different path
(`proxyHTTPUpgrade`):

1. The server hijacks the client connection (`http.Hijacker`).
2. It writes the request onto the stream, reads the app's `101 Switching
   Protocols` response, and forwards the status line + headers back.
3. From that point it falls back to `protocol.Bridge` — a pure bidirectional
   byte copy — so WebSocket frames pass through untouched.

### A TCP tunnel

1. The server binds a public port at registration and starts an accept loop.
   A requested port (`spec.Port`) is honored exactly when free; otherwise a
   port is picked from the configured range (`20000–29999` by default) by
   `allocateTCPPortLocked`.
2. Each accepted client connection is handed a fresh stream and bridged with
   `protocol.Bridge`; the agent dials the local TCP target on the other side.
3. When either end closes, the bridge closes the other end and the stream.

### Disconnect & reconnect

1. Any failure (network drop, server restart, ping timeout) closes the mux.
2. Both sides run cleanup: the server detaches the client, frees hosts and
   ports, and closes TCP listeners; the agent tears down streams.
3. The agent's `Run` loop waits `backoff` (1 s, doubling to a 30 s cap), dials
   again, and re-registers the same tunnels. Clients simply reconnect.

### Graceful close on agent exit

`Agent.Close()` (or the `Run` ctx-cancel path) sends a `close` control message
for every tunnel before tearing down the mux, so the server releases the
endpoints immediately instead of waiting for the keepalive-dead timeout.

### Local-target health & auto-recovery

The agent runs a `healthLoop` that probes each configured local target every
`HealthEvery` (default 5 s, 2 s dial timeout). Consecutive dial failures — from
probes or from stream dials — are counted per tunnel (`tracker`); after
`LocalFailThreshold` (default 3) failures while the tunnel was healthy, the
agent sends `close` for that tunnel and the server frees its endpoint. Once the
target answers again, the agent sends `add` and the server re-assigns a public
URL (`assigned` reply → `OnAssigned` callback). For random-hash HTTP tunnels
the reopened URL is a new random host; pinned TCP ports are rebound to the same
port.

---

## 6. Concurrency model

### Goroutines

| Goroutine | Owner | Purpose |
|---|---|---|
| mux read loop (`Mux.Run`) | both | reads frames, dispatches data/open/close/control/ping |
| mux accept loop (`Agent.acceptLoop`) | agent | accepts peer-opened streams, bridges to local targets |
| keepalive ticker (`Agent.heartbeat`, `Server.keepAlive`) | both | ping cadence / dead-client detection |
| per-stream bridge (`protocol.Bridge`) | both | 2 goroutines per stream, one per direction |
| per-client handshake (`Server.HandleAgent`) | server | handshake + control message loop |
| TCP accept loops (`Server.acceptTCP`) | server | one per public TCP listener |

### Synchronization

- **`Mux.mu`** guards the stream registry and id allocation.
- **`Mux.wmu`** serializes writes so frames never interleave on the wire.
- **`Stream.mu`** guards per-stream close state and the read buffer.
- **`Stream.sig`** (`sync.Once`) guarantees `closed` is signaled exactly once.
- **`Server.mu` (RW)** guards the tunnel registry, agent set and TCP listeners.
  The relay routes each HTTP request through a read lock; registration/detach
  take the write lock.
- **`Agent.mu`** guards the active mux pointer and the shutdown flag.
- **`sync.Once`** everywhere shutdown paths can race (`Mux.Close`,
  `Server.Close`, `client.disconnected`).

### Deadlock rules

- Lock ordering is strictly **never nested** between `Mux.mu`, `Server.mu` and
  stream locks; the only nested acquisition is `Stream.mu` inside helpers that
  then touch `Mux.mu` after releasing `Stream.mu`.
- The mux read loop never blocks on user code except when a stream buffer is
  full (backpressure); close channels are always available as the escape hatch.

---

## 7. Configuration & platform details

### Agent config file

Stored per-user under `os.UserConfigDir()/kproxy/config.json`:

| OS | Path |
|---|---|
| Linux / BSD | `~/.config/kproxy/config.json` |
| macOS | `~/Library/Application Support/kproxy/config.json` |
| Windows | `%AppData%\kproxy\config.json` |

Written with mode `0600`, directories `0700`. `internal/config` exposes
`LoadAgentAt` / `SaveAgentAt` so a custom `--config` path is fully supported.

### Flag / env / config precedence

1. Command-line flags
2. Environment variables (`KPROXY_SERVER`, `KPROXY_API_KEY`)
3. Config file
4. Tunnel file `server_url`/`api_key` (for `kproxy tunnels -f FILE`)
5. Defaults or the interactive first-run prompt

The tunnel config file (`config.LoadTunnelFile`, parsed into specs by
`specsFromFile`) defines `proto`/`local`/`port`/`subdomain`/`domain` per
tunnel plus the security options `basic_auth`/`ip_allow`/`ip_deny`/
`max_request_size`/`request_timeout`; `local` may be a bare port number
meaning `127.0.0.1:<port>`.

### CLI parsing

Go's stdlib `flag` stops at the first positional argument, so the agent CLI
reorders args with `reorderFlagArgs` (in `cmd/kproxy/main.go`): flags are
moved ahead of positionals (while keeping flag/value pairs together via the
`IsBoolFlag` check) before `FlagSet.Parse`. This enables the ergonomic
`kproxy http 8082 --subdomain x` form.

### Cross-platform notes

- **Signals:** both binaries use `signal.NotifyContext` with `SIGINT` +
  `SIGTERM` for graceful shutdown on Unix and Windows.
- **File permissions:** POSIX modes are set for config files; the permission
  assertion in tests is skipped on Windows (the OS ignores `chmod`).
- **Networking:** everything uses `net.Listen`/`net.Dial` with `127.0.0.1`
  loopback defaults for local targets; the control port defaults to `:55555`.

---

## 8. Security internals

- **Agent authentication:** the agent sends `api_key` in its hello; the relay
  delegates validation to a `KeyValidator` (the `store.Store` in production).
  Keys are argon2id-hashed (`internal/auth`) with a sha256 fingerprint as an
  O(1) lookup index; `ValidateKey` rejects unknown, revoked and expired keys
  and returns the key's `KeyIdentity` (ID + `Limits`) for per-key policy.
  A `nil` validator disables the check (relay tests, dev).
- **Per-key limits:** `internal/ratelimit` is a stdlib token bucket used in two
  places — a request-rate bucket checked in `serveHTTP` (excess requests get
  `429` with `Retry-After`) and a bandwidth bucket that paces tunnel bytes in
  both directions (`pacedConn`/`pacedWriter` wrap the stream and the client
  response writer). Limits live on `store.Limits` and travel with the agent's
  `KeyIdentity`. Allowed-subdomain lists are enforced at registration in
  `checkSubdomainAllowed` (claimed subdomains and custom domains must be in the
  list; random-hash hosts are always allowed).
- **Per-tunnel protection (Phase 5):** set by the agent on the tunnel spec,
  enforced by the relay. `applySpecOptions` re-parses `basic_auth`,
  `ip_allow`/`ip_deny` (`parseIPNets`, deny wins), `max_request_size`
  (`units.ParseSize`) and `request_timeout` (`units.ParseTTL`) and rejects
  HTTP-only options on TCP tunnels. Enforcement: Basic auth in `serveHTTP`
  (`401` + `WWW-Authenticate`, constant-time compare); IP checks on every HTTP
  request and on TCP connects (`remoteIP` handles `host:port`); request bodies
  capped via a known-length pre-check and a `sizeLimited` wrapper for
  chunked/unknown bodies — when the cap trips, `http.Request.Write` wraps the
  sentinel in Go's unexported `requestBodyReadError`, so detection falls back
  to a message comparison in `isBodyTooLarge` and the client gets `413`;
  durations bounded with `http.TimeoutHandler` (`503`). Every proxied request
  gets an `X-Request-Id` (`newID(8)`) echoed on responses, upgrades and the
  live `request` event.
- **Custom-domain verification (Phase 5):** enabled by `kproxyd --verify-key`.
  `verifyToken(key, domain)` derives `kproxy-verify-` + hex(sha256(`domain|key`)[:8])
  so tokens are deterministic and offline. `kproxy domain verify-token HOST`
  fetches one over the control API (`GET /api/v1/domains/{domain}/token`,
  `503` when disabled). Registration runs `verifyCustomDomains` *outside* the
  server lock: it queries TXT `_kproxy.<host>` via an injectable `TXTLookup`
  (nil → `net.DefaultResolver`, 5 s timeout), caches verified hosts in
  `Server.verified`, and refuses domains whose records don't match — an
  NXDOMAIN or wrong value returns the exact TXT record to publish.
- **Admin API:** the versioned control API lives in `internal/server` and is
  served on the loopback admin listener (`--admin-addr`) together with the
  embedded dashboard. `internal/admin` now holds the *client* that the CLI uses.
  Requests are authenticated with `--admin-key` (Bearer header or `?token=` for
  the SSE stream) compared in constant time. Requests without an admin key get
  401; an empty `--admin-key` disables the API (503). The same listener serves
  `GET /metrics` (Prometheus text format) behind the admin auth.
- **Metrics (Phase 7):** `internal/metrics` is a stdlib-only registry with
  labeled counters/gauges and a Prometheus text-format renderer. `relay.New`
  registers `kproxy_requests_total` and `kproxy_tunnel_bytes_total`
  (labels `tunnel` + `proto`; counters attributed to the serving agent) plus
  gauge `kproxy_tunnels`, `kproxy_agents`, `kproxy_uptime_seconds` and
  `kproxy_version_info`. `Server.MetricsHandler()` refreshes gauges on each
  scrape; `internal/server` mounts it at `/metrics` behind `admin.Auth`.
- **Keyring (Phase 7):** `internal/keyring` stores secrets under
  `os.UserConfigDir()/kproxy/keyring.json`. On Windows (`win_dpapi.go`,
  `//go:build windows`) values are encrypted with DPAPI in local-machine scope
  (works for service accounts) via `crypt32.dll` syscalls and stored base64 —
  no cgo. On other platforms (`file_plain.go`) the file itself (0600) is the
  protection. `keyring.Resolve` expands `keyring:NAME` references; the CLI
  (`kproxy keyring set|get|rm|list`) and both `--api-key`/`--admin-key`
  resolvers use it.
- **Request logs & replay (Phase 8):** `relay.Server` keeps a bounded ring of
  recent proxied requests (`Config.RequestLogSize`, `kproxyd --request-log`,
  default 1000, 0 = off). Every HTTP request (incl. 101 upgrades) is recorded
  via `publishRequestEvent`, which also emits a structured `slog` line. The
  captured `RequestInfo` redacts aggressively — only the URL *path* is stored;
  query strings, headers and bodies are never captured. `Server.Requests(limit)`
  returns the newest-first snapshot; `internal/server` serves it at
  `GET /api/v1/requests` (`?limit=` capped at 1000) behind `admin.Auth`, and
  `admin.ListRequests` is the CLI client.
- **Control API + dashboard:** `internal/server.NewHandler(srv, store, adminKey)`
  serves `GET /api/v1/tunnels` (live snapshot from `relay.Server.Tunnels()`),
  `GET /api/v1/tunnels/stream` (SSE: `tunnel_open`/`tunnel_close`/`request`
  events from `relay.Server.Subscribe()` with a 15 s heartbeat),
  `GET /api/v1/status` (aggregate from `relay.Server.Status()`),
  `GET /api/v1/domains/{domain}/token` (DNS TXT verification token),
  `GET /api/v1/requests` (bounded replay of recent requests), and key
  CRUD proxied to the store. The dashboard is the built React/Vite app in
  `internal/server/dashboard` embedded with `//go:embed`; rebuild via
  `make web`. The admin CLI is just another client of the same `/api/v1/*`
  routes.
- **Relay events:** `relay.Server` publishes to buffered subscribers
  (`Subscribe()`), non-blocking — slow consumers drop events rather than stall
  the relay. `request` events are emitted from `proxy()` after proxying
  (status + bytes captured via a `statusWriter`); 101 upgrades emit their event
  before bridging. Tunnel open/close events carry a `TunnelInfo` snapshot.
- **TLS:** the public HTTPS listener uses either the ACME manager
  (`golang.org/x/crypto/acme/autocert`, `--acme-email`) or static certificates
  (`--tls-cert`/`--tls-key`). `MinVersion` is TLS 1.2. With static certs the
  control listener is also wrapped in TLS so agents connect via `https://`.
- **ACME host policy:** the autocert manager only issues for the configured
  base domain and its subdomains; every other host is rejected.
- **Randomness:** subdomain hashes and api key secrets use `crypto/rand`.
  Secrets are 128-bit random values with a `kproxy_` prefix and are returned
  exactly once at issuance.
- **Local exposure:** the agent dials localhost only; the dev machine never
  opens an inbound port.
- **Log hygiene:** logs include agent/tunnel identifiers but never the api key.

---

## 9. Testing

### Unit tests — `internal/protocol/mux_test.go`

Cover the multiplexer in isolation over `net.Pipe`:

- bidirectional data flow and `Meta()` propagation
- close signaling → EOF on the peer
- **data flushed before EOF** (write-then-close loses nothing)
- 32 concurrent streams × 200 rounds of request/response
- control frames round-trip
- ping/pong
- mux close terminates live streams
- `protocol.Bridge` byte echo
- **slow stream does not block others** (`TestSlowStreamDoesNotBlockOthers`)
- **`Write` blocks on an exhausted window** (`TestWriteBlocksOnExhaustedWindow`)
- **large transfer round-trip** over the windowed stream
  (`TestLargeTransferRoundTrip`)

### Fuzzing — `internal/protocol/fuzz_test.go`, `internal/relay/fuzz_test.go`

Fuzz targets run as normal tests on their seed corpus and under `go test
-fuzz`:

- `FuzzReadFrame` — frame parser never panics and never accepts a payload
  over `maxFrameSize`
- `FuzzControlRoundTrip` — the JSON control codec is idempotent
  (encode∘decode is a fixed point)
- `FuzzUnmarshalControl` — arbitrary bytes through `UnmarshalControl`/
  `UnmarshalError` never panic
- `FuzzApplySpecOptions` — hostile tunnel specs (`basic_auth`, IP lists, size/
  timeout strings) never panic server-side parsing

### Integration tests — `internal/relay/relay_test.go`

Spin up a real `relay.Server` with HTTP + control listeners and a real
`agent.Agent`:

- HTTP tunnel end-to-end (path routing)
- HTTP body + header forwarding
- custom subdomain allocation
- custom domain allocation
- TCP tunnel end-to-end (byte echo through the public port)
- **TCP port pinning** — a requested public port is honored
- **pinned-port conflict** — an occupied port is rejected with an error
- **multi-tunnel** — one agent registering HTTP + TCP tunnels in a single hello
- **close/add round-trip** — a raw agent unregisters tunnels (`close`) freeing
  hosts/ports, then reopens them (`add`) and gets fresh assignments
- **local-target failure & recovery** — the agent closes a TCP tunnel when its
  local target dies and reopens it on the same pinned port when it recovers
- **WebSocket upgrade** end-to-end (raw 101 handshake + frame echo)
- handshake rejection with a bad api key
- **store-backed auth** — real `store.Store` validates an agent key; a bad key
  is rejected with no reconnect loop
- **subdomain restriction** — a key limited to `["api"]` is welcomed on `api`
  and rejected with `subdomain ... not allowed` on any other
- **request rate limit** — a key at 1 req/s serves 200 then 429
- **relay events** — `Subscribe()` receives `tunnel_open` (with the assigned
  public URL), `request` (path/status for a proxied request) and `tunnel_close`
  as the agent connects and exits
- **basic auth** — a tunnel with `--basic-auth` returns 401 + `WWW-Authenticate`
  without credentials and proxies with the correct ones
- **IP allow/deny** — CIDR allow/deny lists admit and reject clients by remote
  IP; deny wins; a bad CIDR is rejected at registration
- **request size limit** — known-length and chunked bodies over the cap get
  413; bodies under it pass
- **request timeout** — a slow app gets 503 `request timed out`
- **request ID** — `X-Request-Id` flows on the request, response and 101
  upgrade, and shows up in the `request` event
- **per-tunnel counters** — requests/bytes accumulate on `TunnelInfo` and are
  surfaced by `Server.Status()`
- **invalid tunnel options** — malformed basic-auth/IP/size/timeout values and
  HTTP-only options on TCP tunnels are rejected at registration
- **domain verification** — with a fake `TXTLookup`, a verified custom domain
  is honored (cached), an unverified/NXDOMAIN one is rejected with the TXT
  value to publish, and a server without `--verify-key` returns no token
- **load balancing** — two agents claiming the same subdomain both serve
  traffic (least-active / round-robin) and the survivor keeps serving after
  one disconnects (`TestLoadBalancedHTTPTunnels`)
- **request log** — bounded ring retention (newest-first, query strings
  redacted from captured paths) and retention fully disabled when
  `RequestLogSize` is zero

The `testEnv` harness builds a server on ephemeral ports and registers cleanup
with `t.Cleanup`, so tests are hermetic and parallel-safe.

### Control-plane tests — `internal/server/server_test.go`

Exercise the embedded dashboard handler end-to-end over HTTP with a real relay
+ agent:

- 401 on unauthenticated control requests
- empty tunnel list, then a populated one after an agent connects
- key CRUD over `/api/v1/keys` (Authorization bearer)
- `GET /api/v1/status` returns aggregate relay stats (uptime/tunnels/agents/
  request & byte totals) and 401 without auth
- `GET /api/v1/domains/{domain}/token` issues a stable `kproxy-verify-` token
  when verification is enabled and 503 when it is disabled
- SSE stream (`?token=` auth): `text/event-stream` content type and a live
  `request` event flowing through the stream when a request hits the tunnel
- `GET /api/v1/requests` (via `admin.ListRequests`): a bounded newest-first
  replay with the query string redacted, requires auth (401), and rejects a
  bad `limit` (400)

### CLI tests — `cmd/kproxy/main_test.go`

- `reorderFlagArgs` moves flags ahead of positionals, keeping value-taking
  flags paired (`--subdomain myapp`) and `--flag=value` intact
- `specsFromFile` converts a tunnel file into specs (bare-port `local`
  shorthand, `port`, `domain`, and the security fields `basic_auth`/
  `ip_allow`/`ip_deny`/`max_request_size`/`request_timeout`)
- tunnel-file validation errors (no tunnels, bad proto, bad local, bad port)

### Config tests — `internal/config/config_test.go`

- save/load round trip through a temp path
- permission check (POSIX only)
- missing-file → empty config

### Auth / store / admin / ratelimit / units tests

- `internal/auth`: hash→verify round trip, wrong-secret rejection, salted
  hashes, malformed PHC rejection, secret shape
- `internal/store`: create/validate/revoke/expiry, persistence across reloads,
  newest-first listing, secrets never written to the file, limits round-trip
  through the file and into `ValidateKey`'s `KeyIdentity`
- `internal/ratelimit`: take/refill, pacing, large `Wait` beyond the burst,
  unlimited bucket
- `internal/admin`: create/list/revoke over HTTP with auth (401/503/404 paths),
  `ParseTTL` (`d`/`w` suffixes), `ParseSize` (`kb`/`mb`/`gb`), limits round-trip,
  bad size rejected
- `internal/units`: `ParseSize` (`b`/`kb`/`mb`/`gb`, bad input) and `ParseTTL`
  (`ms`/`s`/`m`/`h`/`d`/`w`)
- `internal/metrics`: labeled counter/gauge increment and render to Prometheus
  text format
- `internal/keyring`: set/get/delete/list/resolve round trip, persistence
  across reopen, `keyring:NAME` resolution (incl. missing entry), invalid-name
  rejection — exercising the real Windows DPAPI path in CI
- `internal/protocol`: `TunnelSpec` JSON round-trip preserves the security
  fields and omits them when empty
- `cmd/kproxy` `key` subcommands against a real admin handler (create → list →
  revoke → validation fails; bad admin key → unauthorized)

### Manual smoke test (CLI end-to-end)

The fastest way to sanity-check the real binaries:

```sh
# terminal 1: local app
go run ./examples/demo

# terminal 2: server (dev mode, no TLS)
go build -o bin/kproxyd ./cmd/kproxyd
./bin/kproxyd --domain kproxy.test --http-addr 127.0.0.1:8080 \
  --https-addr "" --control-addr 127.0.0.1:55555 --admin-key test

# terminal 3: issue an agent key, then start the agent
go build -o bin/kproxy ./cmd/kproxy
./bin/kproxy key create --name dev --admin-url http://127.0.0.1:55556 --admin-key test
./bin/kproxy http 8082 --server http://localhost:55555 --api-key kproxy_...

# terminal 4: hit the assigned host (DNS not needed — set Host header)
curl -H "Host: <hash>.kproxy.test" http://127.0.0.1:8080/
```

### CI

`.github/workflows/ci.yml` runs on push/PR across **ubuntu, windows, macos**:
`go vet`, `go test -race -count=1 ./...`, `go build ./cmd/...`, and a portable
dashboard build. A `package` job runs a GoReleaser snapshot and a `smoke`
job (same matrix) extracts each OS's native archive and runs
`kproxy --version`/`kproxyd --version`, so every installer is exercised in
CI. The race detector needs a C compiler, which all three runners provide.

---

## 10. Building & tooling

```sh
make build      # builds bin/kproxy and bin/kproxyd (also rebuilds the dashboard)
make web        # npm build of web/ and copy into internal/server/dashboard (needs node/npm)
make build-agent / make build-server
make dist       # GoReleaser snapshot: archives + deb/rpm for every platform (needs goreleaser)
make docker     # docker build the relay image from packaging/Dockerfile (needs docker)
make test       # go test ./...
make race       # go test -race -count=1 ./...
make fuzz       # brief `go test -fuzz` run over the Fuzz* targets (protocol + relay)
make vet        # go vet ./...
make fmt        # gofmt -l -w cmd internal
make clean
```

The dashboard is a React + Vite app in `web/`. Its production build is copied
into `internal/server/dashboard` (committed) and embedded via `//go:embed`, so
plain `go build` needs no node toolchain. Change `web/`, run `make web`, and
the server picks the new UI up on next build. For UI development run `npm run
dev` in `web/` — Vite proxies `/api` to `http://127.0.0.1:55556`.

Cross-compiling (works on any host):

```sh
GOOS=linux GOARCH=arm64 go build -o kproxyd-linux-arm64 ./cmd/kproxyd
GOOS=windows GOARCH=amd64 go build -o kproxy.exe ./cmd/kproxy
GOOS=darwin GOARCH=arm64 go build -o kproxy-darwin ./cmd/kproxy
```

Vendoring for fully offline builds: `go mod vendor` (results are gitignored
by default; commit them if you want hermetic builds).

Version stamping: build with `-ldflags` to inject `internal/version`:

```sh
go build -ldflags "-X kproxy/internal/version.Commit=$(git rev-parse --short HEAD)"
```

### Releases (GoReleaser)

`.goreleaser.yaml` (v2) cross-compiles both binaries for
linux/darwin/windows × amd64/arm64 with `CGO_ENABLED=0`, stamps version
metadata via ldflags, and produces `.tar.gz`/`.zip` archives plus `.deb`/
`.rpm` packages (`packaging/scripts/*` manage the systemd unit on
install/remove). `internal/buildtool` handles the dashboard copy portably, so
the `before` hook works on any runner. Snapshot locally with `make dist`;
release on a tag via `.github/workflows/release.yml`.

Windows MSIs are built from `packaging/windows/*.wxs` with the WiX v4+
toolset (`dotnet tool install --global wix`) via `packaging/build-msi.ps1`;
the release workflow builds them on a Windows runner and uploads them to the
GitHub release.

### Docker

`packaging/Dockerfile` builds `kproxyd` in `golang:1.24-alpine` (the embedded
dashboard is committed under `internal/server/dashboard`, so no node toolchain
is needed at image build time) and runs on `alpine:3.20` as a non-root user
with CA certificates and a `--data-dir` volume.

---

## 11. How to extend kproxy

### Add a new tunnel protocol (e.g. UDP)

1. Add the proto name constant in `internal/protocol/control.go`.
2. Allocate and bind the public endpoint in `relay.register` (add a branch
   alongside HTTP/TCP) and store its `tunnel` in a new registry map.
3. Start the public accept loop that opens a stream per client (`acceptTCP` is
   the template).
4. The agent needs no changes — it already bridges any stream to its local
   target; add a validation switch in `cmd/kproxy` if you want new flags.

### Add a control-plane API (dashboard / admin CLI)

Implemented in Phase 4 as `internal/server`: a versioned REST surface
(`/api/v1/...`) over `relay.Server` state and the key store, plus the embedded
React/Vite dashboard (`web/` → `internal/server/dashboard` via `//go:embed`).
The dashboard and admin CLI are just clients of that API. To add an endpoint:
define the handler in `internal/server`, mount it on the versioned mux,
publish any backing data as a relay `Event`, and add an admin test. The
dashboard UI is plain React components in `web/src` that call the same routes.

### Add a key store / per-user API keys

Implemented in Phase 3 as `internal/store` (atomic JSON file, stdlib-only,
per the project's single-dependency rule) + `internal/auth` (argon2id) +
`internal/admin` (loopback HTTP API). The relay's `AdminKey` was replaced by
the `KeyValidator` interface; `cmd/kproxyd` wires the file store in. Per-key
rate/bandwidth limits hook into `relay.serveHTTP`/the bridge via
`internal/ratelimit` buckets built from the `KeyIdentity` returned during
registration; allowed-subdomain lists are enforced in
`checkSubdomainAllowed`. To extend: add fields to `store.key`/`KeyInfo`, expose
them in `internal/admin`, and surface them in `kproxy key ...`.

### Add agent features

1. Add flags in `cmd/kproxy/main.go` (and to `reorderFlagArgs` if it takes
   values).
2. Thread the option through `agent.Config`.
3. Implement the logic in `internal/agent`.

### Conventions when extending

- Keep the **agent dumb**: it bridges bytes; all protocol/HTTP logic lives on
  the server.
- Every exported symbol needs a Go doc comment (they render in godoc and lint).
- New behavior needs a test in the matching `_test.go`, using the existing
  harnesses.

---

## 12. Status & roadmap

**Implemented (Phases 0–8):** protocol & multiplexer, HTTP + TCP tunnels,
hash / custom subdomains, custom domains, TCP port pinning, multi-tunnel
config files, WebSocket upgrades, reconnect with backoff, keepalives,
graceful tunnel close + local-target auto-recovery, per-user API keys
(argon2id hashing, expiry, revocation, loopback admin API) with per-key rate
(429), bandwidth-pacing and allowed-subdomain limits, per-tunnel basic auth,
IP allow/deny lists, request body caps (413) and timeouts (503), request IDs,
DNS TXT custom-domain verification (`--verify-key` + `kproxy domain
verify-token`), versioned control API (`/api/v1/*`), live tunnel list +
real-time request inspector (SSE) + key CRUD in an embedded React dashboard,
TLS (ACME + static certs), config persistence, JSON logs, CI, full test
suite, cross-platform build, packaging (GoReleaser archives + deb/rpm +
Windows MSI via WiX, systemd unit, Docker image, one-command bootstrap),
Prometheus metrics (`/metrics` behind admin auth), load-balanced tunnels
(`tunnelSet`), per-stream flow control (`FrameWindow`), OS-keyring secret
storage (DPAPI on Windows), fuzzing of the frame parser + control codec, and
structured request logs with bounded redacted replay (`/api/v1/requests`,
`kproxy requests`).

---

## 13. Coding conventions

- **Style:** `gofmt`-formatted; `go vet` clean. Run `make fmt` before pushing.
- **Errors:** wrap with `%w` for context; exported sentinel errors in
  `protocol` (`ErrMuxClosed`, `ErrStreamClosed`); prefer `errors.Is`.
- **Logging:** `log/slog`, structured key/value pairs, `--json`/`--verbose`
  toggles handled at the CLI boundary.
- **Naming:** packages are lowercase single words; types mirror the domain
  (`Mux`, `Stream`, `tunnel`, `client`).
- **No `init()` side effects** beyond package constants; construct everything
  explicitly (`relay.New`, `agent.New`, `protocol.NewMux`).
- **Tests:** table-driven where sensible, `t.Helper()`, hermetic ports, no
  sleeps where a channel/`select` with timeout will do.
- **No inline comments for the obvious** — comments explain *why*, not *what*,
  and exported identifiers get godoc-style doc comments.

---

### License

MIT