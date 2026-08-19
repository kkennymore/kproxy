GO ?= go
NPM ?= npm
GORELEASER ?= goreleaser
BIN := bin
WEB_DIST := internal/server/dashboard

.PHONY: all build build-server build-agent web test vet fmt race clean dist docker install

all: build

build: web build-agent build-server

# Build the embedded dashboard from the React/Vite app. web/dist is copied
# into internal/server/dashboard so plain `go build` needs no node toolchain.
web:
	$(NPM) --prefix web run build
	$(GO) run ./internal/buildtool -clean web/dist $(WEB_DIST)

build-agent:
	$(GO) build -o $(BIN)/kproxy ./cmd/kproxy

build-server:
	$(GO) build -o $(BIN)/kproxyd ./cmd/kproxyd

test:
	$(GO) test ./...

race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w cmd internal pkg

install:
	$(GO) install ./cmd/kproxy ./cmd/kproxyd

# Build all release artifacts locally (no publish): archives + deb/rpm.
dist:
	$(GORELEASER) release --snapshot --clean

# Build the relay Docker image (multi-arch via `docker buildx build`).
docker:
	docker build -t kproxyd:latest -f packaging/Dockerfile .

clean:
	$(GO) run ./internal/buildtool -rm $(BIN) -rm dist -rm data -rm web/dist -rm $(WEB_DIST)
