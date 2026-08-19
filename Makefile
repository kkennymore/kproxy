GO ?= go
BIN := bin

.PHONY: all build build-server build-agent test vet fmt race clean install

all: build

build: build-agent build-server

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

clean:
	rm -rf $(BIN) dist data
