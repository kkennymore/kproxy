# kproxy roadmap

## Status

Phase 0 and Phase 1 are implemented and tested. Remaining phases extend the
foundation without redesigning it.

## Phase 2 — Multi-tunnel & multi-agent hardening

- Multiple tunnels per agent process (works today; polish CLI ergonomics).
- Tunnel pinning for TCP ports (`kproxy tcp 22 --port 2200`).
- Graceful tunnel close on agent exit and on local target failure.
- Config file for tunnels (YAML/JSON) so a developer can define several
  tunnels and start them all at once.

## Phase 3 — API keys & auth (control plane)

- Replace the shared `--admin-key` with per-user API keys:
  - `internal/auth`: issue/revoke/list/expiry.
  - Keys hashed with argon2id; plaintext shown once at issuance.
- `internal/store`: SQLite (pure-Go, `modernc.org/sqlite`) persistence for
  keys, tunnel history, usage counters.
- Per-key limits: request rate, bandwidth cap, allowed subdomains.
- `kproxy` admin subcommands to manage keys remotely:
  `kproxy key create`, `kproxy key revoke`, `kproxy key list`.
- Agent first-run flow already prompts for a key and persists it (Phase 1);
  wire it to the real key store.

## Phase 4 — Web dashboard

- `web/` React + Vite app, embedded into `kproxyd` via `//go:embed`.
- Live tunnel list, request inspector (headers/body streamed over SSE),
  key CRUD and per-key usage, admin login separate from API keys.
- The control API grows a versioned REST surface (`/api/v1/...`) consumed by
  both the dashboard and the admin CLI.

## Phase 5 — Edge features

- Per-tunnel `--basic-auth user:pass`, IP allow/deny lists.
- Custom domain verification (prove ownership before `--domain` is honored).
- HTTP request size / duration limits, request ID + tracing headers.
- Tunnel metadata and status endpoint (`/api/v1/tunnels`).

## Phase 6 — Packaging & cross-platform

- GoReleaser: Windows (zip, MSI), Linux (deb, rpm, tar.gz), macOS (zip, pkg),
  amd64 + arm64.
- systemd unit, Docker multi-arch image, one-command server bootstrap script.
- Smoke-test every installer in CI on all three OS families.

## Phase 7 — Hardening & observability

- Prometheus `/metrics` (tunnels, streams, bandwidth, latency).
- Structured request logs with redaction; optional replay/log retention.
- Load-balancing tunnels: several agents share one subdomain (round-robin).
- Flow control (per-stream window) and resource limits.
- Security audit: TLS settings, token storage (OS keyring), fuzzing of the
  frame parser.

## Extension guide

- New tunnel protocol: add a `Proto` value in `internal/protocol`, an
  allocation branch in `relay.register`, and a listener in `kproxyd`.
- New control-plane API: keep it versioned under `internal/server`; the
  dashboard and admin CLI are just clients of the same HTTP API.
- New agent feature: add flags in `cmd/kproxy`, pass through `agent.Config`,
  keep all logic in `internal/agent`.
