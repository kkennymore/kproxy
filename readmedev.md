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
│   └── kproxyd/                relay daemon (listeners, TLS/ACME, shutdown)
├── internal/
│   ├── agent/                  agent control loop, reconnect/backoff, accept loop
│   ├── config/                 agent config file persistence
│   ├── protocol/               wire framing, stream multiplexer, control msgs
│   ├── relay/                  server registry, host/port allocation, routing
│   └── version/                version/commit injection
├── examples/demo/              tiny web app for manual smoke tests
├── docs/
│   ├── architecture.md         high-level design & deployment notes
│   └── roadmap.md              phased plan
├── .github/workflows/ci.yml    CI matrix (vet + race test + build, 3 OSes)
├── Makefile                    build/test/vet/race targets
├── go.mod / go.sum             module definition
└── README.md                   end-user documentation
```

| Package | Responsibility | Key types |
|---|---|---|
| `protocol` | Wire format, multiplexing, byte bridge | `Mux`, `Stream`, `FrameType`, `Hello`/`Welcome`/`ErrorMsg` |
| `relay` | Server-side tunnel bookkeeping and routing | `Server`, `client`, `tunnel` |
| `agent` | Client-side lifecycle and bridging | `Agent` |
| `config` | Config file read/write | `AgentConfig` |

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

### Control messages (JSON)

Control frames flow over stream id 0 and carry one of these payloads:

**`hello`** (agent → server, first message):

```json
{
  "type": "hello",
  "version": "0.1.0",
  "api_key": "secret",
  "tunnels": [
    {"id": "main", "proto": "http", "local": "127.0.0.1:8082", "subdomain": "", "domain": ""}
  ]
}
```

**`welcome`** (server → agent, success reply):

```json
{
  "type": "welcome",
  "version": "0.1.0",
  "server": "example.com",
  "tunnels": [{"id": "main", "public_url": "https://7f3a9c21.example.com"}]
}
```

**`error`** (server → agent, fatal handshake failure):

```json
{"type": "error", "message": "invalid api key"}
```

The `type` field disambiguates; the wire types are defined in
`internal/protocol/control.go` (`TypeHello`, `TypeWelcome`, `TypeError`,
`ProtoHTTP`, `ProtoTCP`).

### Stream lifecycle

1. **Open:** the server allocates an id via `Mux.Open(tunnelID)`, registers the
   local `Stream`, and sends a `FrameOpen`. The agent's read loop creates its
   counterpart and pushes it onto the accept queue; its `Meta()` is the tunnel
   id used to find the local target.
2. **Data:** each side writes `FrameData` frames tagged with the stream id. The
   receiver buffers chunks in a per-stream channel (`streamRecvCap`, 256
   chunks) and the consumer reads them through the `net.Conn` adapter.
3. **Close:** either side sends `FrameClose`; the peer's reader observes EOF
   once buffered data drains. A stream is evicted from the map only after both
   sides have closed (this guarantees no data is lost in flight).
4. **Teardown:** `Mux.Close()` force-terminates every live stream and closes
   the underlying connection.

### The `net.Conn` adapter

`protocol.Stream` implements `net.Conn`. This is what lets both the agent and
the server use plain `io.Copy`/`net/http` against streams as if they were real
sockets:

- `Read` drains the per-stream buffer channel; returns `io.EOF` after the peer
  closes and buffered data is exhausted.
- `Write` sends a `FrameData`.
- `SetDeadline*` are no-ops (deadlines are managed at the mux/HTTP layer).

### Keepalive / liveness

- The agent sends a `Ping` every 30 s and expects a `Pong` within 5 s
  (`Mux.Ping`).
- The server also pings every 30 s and additionally drops any client with no
  frames for 90 s (`keepAliveDead`).
- A failed ping closes the mux, which triggers the agent's reconnect path.

### Flow control (current limitation)

Backpressure is **per-connection**: when a stream's receive buffer is full,
the mux read loop stalls, which slows all streams on the same tunnel until the
consumer catches up. This is safe (nothing is dropped) but means one slow
consumer can affect throughput of others. Explicit per-stream windows are
planned (roadmap Phase 7).

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
   base domain gets a landing page, `/healthz` returns JSON status).
3. The server calls `client.openStream(tunnelID)` → sends `FrameOpen` and gets
   a `Stream`.
4. The server serializes the incoming request onto the stream with
   `r.Write(stream)` (handles body, content-length/chunked, trailers).
5. The agent's accept loop dials `127.0.0.1:8082` and bridges bytes, so the
   request bytes reach the app exactly as written.
6. The app's raw response travels back; the server reads it with
   `http.ReadResponse` and writes status, headers and body to the client.

### A WebSocket / upgrade request

Upgrade requests (any `Connection: upgrade`) take a different path
(`proxyHTTPUpgrade`):

1. The server hijacks the client connection (`http.Hijacker`).
2. It writes the request onto the stream, reads the app's `101 Switching
   Protocols` response, and forwards the status line + headers back.
3. From that point it falls back to `protocol.Bridge` — a pure bidirectional
   byte copy — so WebSocket frames pass through untouched.

### A TCP tunnel

1. The server binds a public port (range `20000–29999` by default) at
   registration and starts an accept loop.
2. Each accepted client connection is handed a fresh stream and bridged with
   `protocol.Bridge`; the agent dials the local TCP target on the other side.
3. When either end closes, the bridge closes the other end and the stream.

### Disconnect & reconnect

1. Any failure (network drop, server restart, ping timeout) closes the mux.
2. Both sides run cleanup: the server detaches the client, frees hosts and
   ports, and closes TCP listeners; the agent tears down streams.
3. The agent's `Run` loop waits `backoff` (1 s, doubling to a 30 s cap), dials
   again, and re-registers the same tunnels. Clients simply reconnect.

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
4. Defaults or the interactive first-run prompt

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

- **Authentication:** the agent sends `api_key` in its hello; the server
  compares it to the configured `--admin-key`. An empty admin key disables the
  check (dev only). Phase 3 replaces this with per-user hashed API keys.
- **TLS:** the public HTTPS listener uses either the ACME manager
  (`golang.org/x/crypto/acme/autocert`, `--acme-email`) or static certificates
  (`--tls-cert`/`--tls-key`). `MinVersion` is TLS 1.2. With static certs the
  control listener is also wrapped in TLS so agents connect via `https://`.
- **ACME host policy:** the autocert manager only issues for the configured
  base domain and its subdomains; every other host is rejected.
- **Randomness:** subdomain hashes use `crypto/rand`.
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

### Integration tests — `internal/relay/relay_test.go`

Spin up a real `relay.Server` with HTTP + control listeners and a real
`agent.Agent`:

- HTTP tunnel end-to-end (path routing)
- HTTP body + header forwarding
- custom subdomain allocation
- custom domain allocation
- TCP tunnel end-to-end (byte echo through the public port)
- **WebSocket upgrade** end-to-end (raw 101 handshake + frame echo)
- handshake rejection with a bad api key

The `testEnv` harness builds a server on ephemeral ports and registers cleanup
with `t.Cleanup`, so tests are hermetic and parallel-safe.

### Config tests — `internal/config/config_test.go`

- save/load round trip through a temp path
- permission check (POSIX only)
- missing-file → empty config

### Manual smoke test (CLI end-to-end)

The fastest way to sanity-check the real binaries:

```sh
# terminal 1: local app
go run ./examples/demo

# terminal 2: server (dev mode, no TLS)
go build -o bin/kproxyd ./cmd/kproxyd
./bin/kproxyd --domain kproxy.test --http-addr 127.0.0.1:8080 \
  --https-addr "" --control-addr 127.0.0.1:55555 --admin-key test

# terminal 3: agent
go build -o bin/kproxy ./cmd/kproxy
./bin/kproxy http 8082 --server http://localhost:55555 --api-key test

# terminal 4: hit the assigned host (DNS not needed — set Host header)
curl -H "Host: <hash>.kproxy.test" http://127.0.0.1:8080/
```

### CI

`.github/workflows/ci.yml` runs on push/PR across **ubuntu, windows, macos**:
`go vet`, `go test -race -count=1 ./...`, and `go build ./cmd/...`. The race
detector needs a C compiler, which all three runners provide.

---

## 10. Building & tooling

```sh
make build      # builds bin/kproxy and bin/kproxyd
make build-agent / make build-server
make test       # go test ./...
make race       # go test -race -count=1 ./...
make vet        # go vet ./...
make fmt        # gofmt -l -w cmd internal
make clean
```

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

Phase 4 introduces a versioned REST surface (`/api/v1/...`) in a new
`internal/server` package. Keep it a thin layer over `relay.Server` state and
the future `internal/store`. The dashboard and admin CLI are just clients of
that API.

### Add a key store / per-user API keys

Phase 3: introduce `internal/store` backed by pure-Go SQLite
(`modernc.org/sqlite`). Hash keys with argon2id from `golang.org/x/crypto`.
Replace the single `adminKey` comparison in `relay.HandleAgent` with a lookup
in the store.

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

**Implemented:** protocol & multiplexer, HTTP + TCP tunnels, hash / custom
subdomains, custom domains, WebSocket upgrades, reconnect with backoff,
keepalives, TLS (ACME + static certs), admin-key auth, config persistence,
JSON logs, CI, full test suite, cross-platform build.

**Planned (see [docs/roadmap.md](docs/roadmap.md)):**

1. **Phase 2** — multi-tunnel ergonomics, TCP port pinning, tunnel config file.
2. **Phase 3** — real API-key store (argon2id + SQLite), expiry, per-key
   rate/bandwidth limits, admin CLI.
3. **Phase 4** — web dashboard (React + Vite, embedded via `//go:embed`),
   live request inspector, key CRUD.
4. **Phase 5** — per-tunnel basic auth, IP allowlists, domain verification,
   request limits.
5. **Phase 6** — packaging: GoReleaser (deb/rpm/MSI/pkg/zip), systemd, Docker.
6. **Phase 7** — hardening: Prometheus metrics, flow control, load-balanced
   tunnels, OS keyring, fuzzing.

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