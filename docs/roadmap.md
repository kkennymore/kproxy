# kproxy roadmap

## Status

Phases 0–7 are implemented and tested. Remaining phases extend the foundation
without redesigning it.

## Phase 2 — Multi-tunnel ergonomics ✅

Done:

- TCP port pinning — `kproxy tcp 22 --port 2200` (honored exactly when free;
  occupied ports are rejected with a clear error). Added `Port` to
  `protocol.TunnelSpec`, honored in `relay.allocateTCPPortLocked`.
- Tunnel config file (JSON) — `kproxy tunnels -f tunnels.json` starts many
  tunnels from one process. Supports `proto`/`local` (bare port shorthand)/
  `port`/`subdomain`/`domain`, with optional `server_url`/`api_key` fallbacks
  (`internal/config.LoadTunnelFile`, `cmd/kproxy.specsFromFile`).
- Graceful tunnel close — `close`/`add`/`assigned` control messages. Agent
  exit releases all endpoints immediately; a dead local target closes its
  tunnel (server frees host/port) and auto-reopens it on recovery (same pinned
  port, new random host otherwise).
- Tests: pinned-port, pinned-port conflict, multi-tunnel, close/add round-trip,
  local-failure close & recovery integration; CLI unit tests for
  `reorderFlagArgs` and `specsFromFile`.

## Phase 3 — API keys & auth (control plane)

Done:

- Per-user API keys replacing the shared `--admin-key` for agents.
  - `internal/auth`: argon2id hashing (salted PHC strings) + secret
    generation (`kproxy_` + 128-bit random).
  - `internal/store`: atomic JSON file store (`--data-dir/keys.json`,
    stdlib-only to preserve the single-dependency rule). Stores argon2id
    hashes + a sha256 fingerprint as an O(1) lookup index; `ValidateKey`
    rejects unknown / revoked / expired keys and returns a `KeyIdentity`
    (ID + policy limits) for per-key enforcement. Secrets are never
    persisted.
  - `internal/admin`: loopback admin HTTP API (`--admin-addr`, default
    `127.0.0.1:55556`), Bearer-auth with `--admin-key`
    (POST/DELETE/GET `/v1/keys`).
  - `relay` validates agents via the `KeyValidator` interface and enforces
    limits from the returned identity.
- Per-key limits (`internal/ratelimit`, stdlib token bucket):
  - HTTP request rate (`--rate`): excess requests get `429` + `Retry-After`.
  - Bandwidth (`--bandwidth`, sizes like `1mb`/`512kb`): tunnel bytes paced
    in both directions (stream and client-response wrappers).
  - Allowed subdomains (`--subdomain api,staging`): claimed subdomains and
    custom domains must be in the list; random-hash hosts always allowed.
- `kproxy key create|revoke|list` (with `--name`, `--ttl` incl. `d`/`w`,
  `--rate`, `--bandwidth`, `--subdomain`, `--admin-url`, `--admin-key`).
- Agent stops retrying permanent server rejections (bad/revoked/expired
  key exits with the server's message instead of reconnecting forever) and
  prints a `kproxy key create` hint on rejection.
- Tests: auth (hash/verify/salt), store (create/revoke/expiry/persistence,
  no-secret-leak, limits round-trip), ratelimit (take/refill/pacing),
  admin (auth + CRUD over HTTP, ParseTTL/ParseSize, limits round-trip),
  relay (fake validator + real-store auth incl. no-reconnect on bad key,
  subdomain restriction, 200-then-429 rate limit), CLI key subcommands.
  Smoke-tested end-to-end with the real binaries (create-with-limits,
  disallowed-subdomain rejection + hint, 200/200/429).

## Phase 4 — Web dashboard ✅

Done:

- `web/` React + Vite app (single third-party JS dependency set; no other
  runtime deps), embedded into `kproxyd` via `//go:embed` (`internal/server/
  dashboard`). Built with `make web` (npm build + copy into the embed dir) so
  a plain `go build` needs no node toolchain.
- Control plane served on the admin listener (`--admin-addr`). Admin login is
  separate from agent API keys (token kept in sessionStorage; Bearer header
  for fetch, `?token=` for the SSE stream since EventSource cannot set
  headers).
- Versioned REST surface `/api/v1/*` consumed by both the dashboard and the
  admin CLI (the admin CLI was migrated off `/v1/keys`):
  - `GET /api/v1/tunnels` — live tunnel list (`internal/server`), 401/503
    handling.
  - `GET /api/v1/tunnels/stream` — SSE event feed with heartbeat; publishes
    relay events.
  - `POST /api/v1/keys`, `DELETE /api/v1/keys/{id}`, `GET /api/v1/keys`.
- Live request inspector: `internal/relay` now publishes `tunnel_open`,
  `tunnel_close` and `request` events (host/method/path/status/duration/bytes,
  incl. 101 upgrades) to buffered subscribers; the dashboard renders them in
  real time. Slow subscribers drop events instead of blocking the relay.
- Dashboard pages: login, live tunnel list (public URL / proto / local /
  agent / opened-at), live request inspector, API-key CRUD with per-key limit
  display and one-time secret reveal.
- Tests: relay events (open/close/request), control API over HTTP (401 auth,
  empty list, key CRUD, live tunnel list, SSE `request` event over the stream).
  Smoke-tested end-to-end with the real binaries (dashboard HTML served,
  key create with limits, agent tunnel listed, proxied request + live SSE
  request event, 401 for bad admin key).

## Phase 5 — Edge features ✅

Done:

- Per-tunnel protection, enforced by the relay (agent-set, server-enforced):
  - HTTP Basic auth (`--basic-auth user:pass`); missing/incorrect credentials
    get `401` + `WWW-Authenticate: Basic`.
  - IP allow/deny lists (`--ip-allow`, `--ip-deny`, IP or CIDR). Deny wins;
    empty allow admits everyone not denied. Enforced for HTTP tunnels on each
    request and for TCP tunnels at connect time. New `internal/units` package
    (`ParseSize`, `ParseTTL`) shared by `internal/admin` and the relay.
  - Request body caps (`--max-request-size`, e.g. `1mb`): known-length bodies
    rejected up front (`413`); chunked/unknown bodies wrapped in `sizeLimited`
    (the agent-visible error travels through `http.Request.Write`; the relay
    answers `413` when it surfaces).
  - Request duration bounds (`--request-timeout`, e.g. `30s`): applied via
    `http.TimeoutHandler` (`503 "request timed out"`).
  - Request IDs: `X-Request-Id` header on every proxied request (upstream +
    response, incl. 101 upgrades) and in the live `request` event.
  - Options are validated client-side and re-parsed/validated server-side in
    `applySpecOptions`; HTTP-only options are rejected on TCP tunnels.
- Custom-domain verification via DNS TXT:
  - `kproxyd --verify-key SECRET` enables it. Tokens are derived deterministically
    (`sha256(domain|key)`, `kproxy-verify-` + first 8 hex chars), so
    `kproxy domain verify-token HOST` needs no network round trip and is
    always stable. The operator publishes TXT `_kproxy.<host>`; the relay
    checks it (injected `TXTLookup` for tests; nil → `net.DefaultResolver`)
    before honoring `--domain`, caches verified hosts, and refuses unverified
    ones with the exact value to publish. Verification is skipped entirely
    when `--verify-key` is empty (existing custom-domain behavior unchanged).
  - Control API: `GET /api/v1/domains/{domain}/token` (`503` when disabled),
    `GET /api/v1/status` (uptime/tunnels/agents/request & byte totals).
  - Dashboard tunnels table now shows per-tunnel request counts and traffic.
- Tunnel status/metadata: per-tunnel atomic request/byte counters + last-active
  time, agent connected-at, exposed in `TunnelInfo` and aggregated in
  `Server.Status()`.
- Config-file support for the new fields (`basic_auth`, `ip_allow`, `ip_deny`,
  `max_request_size`, `request_timeout`) via `internal/config.TunnelEntry`.
- Tests: relay (basic auth incl. 401+WWW-Authenticate, IP allow/deny incl.
  deny-wins and CIDR, known-length + chunked size limits → 413, timeout → 503,
  request-ID propagation, per-tunnel counters, invalid-options rejection,
  domain verification incl. disabled + NXDOMAIN + verified cache), server
  (status + domain-token routes, 503 when disabled), protocol TunnelSpec JSON
  round-trip, CLI `specsFromFile` with the new fields.

## Phase 6 — Packaging & cross-platform ✅

Done:

- **GoReleaser** (`.goreleaser.yaml`, v2) builds both binaries for
  linux/darwin/windows × amd64/arm64 (`CGO_ENABLED=0`):
  - Archives: `.tar.gz` (linux) and `.zip` (windows/darwin), each containing
    both binaries + `README.md` + `LICENSE` + `checksums.txt`.
  - Linux packages via nfpm: `.deb` and `.rpm` for amd64/arm64, installing
    `kproxyd` to `/usr/bin`, the systemd unit to `/lib/systemd/system`, and
    license to `/usr/share/doc`; postinstall/postremove scripts manage the
    unit.
  - `internal/version` is stamped with `-X` ldflags (Version/Commit/Date).
- **systemd unit** (`packaging/kproxyd.service`): hardened (DynamicUser,
  ProtectSystem=strict, NoNewPrivileges), reads `/etc/kproxy/kproxyd.env`,
  uses `StateDirectory=kproxy`; a drop-in grants `CAP_NET_BIND_SERVICE` for
  :80/:443.
- **Windows MSI** (`packaging/windows/*.wxs`, `packaging/build-msi.ps1`)
  via the WiX v4+ toolset (`dotnet tool install --global wix`); installs
  each binary to `%ProgramFiles%`. The release workflow builds them on a
  Windows runner and uploads them to the GitHub release.
- **Docker** (`packaging/Dockerfile`): multi-stage, `golang:1.24-alpine`
  build with the embedded dashboard (committed `web/dist`, so no node needed
  at image build time), `alpine:3.20` runtime with CA certs, non-root user,
  `--data-dir /var/lib/kproxy` volume; `make docker`.
- **One-command bootstrap** (`packaging/install-kproxyd.sh`): detects
  arch, downloads the latest release from GitHub, installs to
  `/usr/local/bin`, writes `/etc/kproxy/kproxyd.env`, installs the systemd
  unit + capability drop-in, and starts the service.
- **CI**: `ci.yml` gained a `package` job that runs a GoReleaser snapshot and
  a `smoke` job (matrix ubuntu/windows/macos) that extracts the native
  archive and runs `kproxy --version`/`kproxyd --version` on every OS.
  `release.yml` publishes archives + deb/rpm on tags and builds/uploads MSIs.
  The dashboard-build step is now portable (npm + `internal/buildtool`
  instead of `make`), so it works on every runner.
- **Makefile**: `make dist` (local snapshot), `make docker`.
- Smoke-tested locally on Windows: GoReleaser snapshot (12 binaries, 6
  archives, 4 packages), archive `--version`, silent MSI install → run →
  uninstall for both kproxy and kproxyd, and the deb layout.

## Phase 7 — Hardening & observability ✅

Done:

- **Prometheus metrics** (`internal/metrics`): stdlib-only registry with
  labeled counters/gauges and text-format rendering. The relay exports
  `GET /metrics` on the admin listener behind `admin.Auth`:
  `kproxy_requests_total`, `kproxy_tunnel_bytes_total` (both keyed by
  `tunnel` + `proto`), `kproxy_tunnels`, `kproxy_agents`, uptime and version
  gauges. HTTP/TCP/upgrade paths increment and attribute bytes to the serving
  agent.
- **Flow control** (`internal/protocol/mux.go`): per-stream byte buffer with a
  256 KB send window; peers grant `FrameWindow` as the consumer drains half
  the window, and a `Write` blocks until credit is replenished. A slow
  consumer no longer stalls other streams, the receive buffer is capped at
  2× the window, and the frame reader is extracted for fuzzing.
- **Load-balanced tunnels** (`internal/relay`): HTTP tunnels are grouped in a
  `tunnelSet`; several agents may claim the same subdomain and public traffic
  is distributed by least-active-connections (round-robin on ties). A dead
  agent is removed from the set on disconnect and the survivor keeps serving.
- **OS keyring** (`internal/keyring`): Windows secrets are encrypted with
  DPAPI (local-machine scope, works for services) before being written to
  `%APPDATA%\kproxy\keyring.json`; macOS/Linux use an owner-only (0600) JSON
  file (no cgo). `--api-key`/`--admin-key` accept `keyring:NAME` references,
  and `kproxy keyring set|get|rm|list` manages entries (stdin for `set`).
  kproxyd's `--admin-key` resolves the same way.
- **Fuzzing**: `FuzzReadFrame` (frame parser, payload-size cap),
  `FuzzControlRoundTrip` (JSON codec stability), `FuzzUnmarshalControl`,
  `FuzzApplySpecOptions` (hostile tunnel specs). `go test -fuzz` runs green.

Remaining candidates from the original Phase 7 scope (structured request logs
with retention) are tracked below for a future phase.

## Phase 8 — Observability extras (candidate)

- Structured request logs with redaction; optional replay/log retention.

## Extension guide

- New tunnel protocol: add a `Proto` value in `internal/protocol`, an
  allocation branch in `relay.register`, and a listener in `kproxyd`.
- New control-plane API: keep it versioned under `internal/server`; the
  dashboard and admin CLI are just clients of the same HTTP API.
- New agent feature: add flags in `cmd/kproxy`, pass through `agent.Config`,
  keep all logic in `internal/agent`.
