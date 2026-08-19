# Build stage: compile kproxyd with the embedded dashboard (web/dist is
# committed into internal/server/dashboard, so no node toolchain is needed).
FROM golang:1.24-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w -X kproxy/internal/version.Version=${VERSION} -X kproxy/internal/version.Commit=${COMMIT}" \
    -o /out/kproxyd ./cmd/kproxyd

# Runtime stage.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && addgroup -S kproxy && adduser -S -G kproxy kproxy
COPY --from=build /out/kproxyd /usr/local/bin/kproxyd
RUN mkdir -p /var/lib/kproxy && chown -R kproxy:kproxy /var/lib/kproxy
USER kproxy
VOLUME ["/var/lib/kproxy"]
EXPOSE 80 443 55555 20000-29999
ENTRYPOINT ["/usr/local/bin/kproxyd", "--data-dir", "/var/lib/kproxy"]