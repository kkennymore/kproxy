// Command kproxyd is the kproxy relay server daemon. It exposes public HTTP
// and TCP endpoints that route over tunnels opened by kproxy agents.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"kproxy/internal/keyring"
	"kproxy/internal/relay"
	"kproxy/internal/server"
	"kproxy/internal/store"
	"kproxy/internal/version"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("kproxyd failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var (
		controlAddr = flag.String("control-addr", ":55555", "listen address for agent control connections")
		httpAddr    = flag.String("http-addr", ":80", "listen address for public http")
		httpsAddr   = flag.String("https-addr", ":443", "listen address for public https (empty disables)")
		domain      = flag.String("domain", "", "base domain for tunnel subdomains")
		adminKey    = flag.String("admin-key", "", "secret that authenticates admin API requests (key create/revoke/list)")
		adminAddr   = flag.String("admin-addr", "127.0.0.1:55556", "listen address for the admin API (empty disables)")
		verifyKey   = flag.String("verify-key", "", "secret for custom-domain DNS verification (enables _kproxy.<domain> TXT checks)")
		tcpRange    = flag.String("tcp-port-range", "20000-29999", "public port range for tcp tunnels")
		tlsCert     = flag.String("tls-cert", "", "path to TLS certificate (also used for the control listener)")
		tlsKey      = flag.String("tls-key", "", "path to TLS private key")
		acmeEmail   = flag.String("acme-email", "", "email for LetsEncrypt; enables automatic certs")
		dataDir     = flag.String("data-dir", "./data", "directory for certificate cache, key store and runtime state")
		requestLog  = flag.Int("request-log", 1000, "number of recent proxied requests kept for replay via /api/v1/requests (0 disables)")
		verbose     = flag.Bool("verbose", false, "verbose logging")
		jsonOut     = flag.Bool("json", false, "json log output")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Fprintf(os.Stdout, "kproxyd %s\n", version.String())
		return nil
	}
	if *domain == "" {
		return errors.New("--domain is required")
	}
	start, end, err := parsePortRange(*tcpRange)
	if err != nil {
		return err
	}
	if *httpsAddr != "" && *tlsCert == "" && *acmeEmail == "" {
		return errors.New("--https-addr requires --tls-cert/--tls-key or --acme-email")
	}
	if *tlsCert == "" && *tlsKey != "" || *tlsCert != "" && *tlsKey == "" {
		return errors.New("--tls-cert and --tls-key must be provided together")
	}

	logger = buildLogger(*verbose, *jsonOut)
	logger.Info("starting kproxyd",
		"version", version.String(),
		"domain", *domain,
		"control", *controlAddr,
		"http", *httpAddr,
		"https", *httpsAddr,
	)

	scheme := "http"
	if *httpsAddr != "" {
		scheme = "https"
	}

	keyStore, err := store.Open(filepath.Join(*dataDir, "keys.json"))
	if err != nil {
		return fmt.Errorf("open key store: %w", err)
	}
	logger.Info("key store ready", "path", filepath.Join(*dataDir, "keys.json"), "keys", len(keyStore.List()))

	srv := relay.New(relay.Config{
		Domain:         *domain,
		Scheme:         scheme,
		Keys:           keyStore,
		TCPStart:       start,
		TCPEnd:         end,
		VerifyKey:      *verifyKey,
		Logger:         logger,
		RequestLogSize: *requestLog,
	})

	var staticTLS *tls.Config
	if *tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return fmt.Errorf("load tls keypair: %w", err)
		}
		staticTLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 4)

	go serveControl(ctx, errCh, *controlAddr, staticTLS, srv)

	handlers := []*http.Server{}
	if *adminAddr != "" {
		if *adminKey == "" {
			return errors.New("--admin-addr requires --admin-key to authenticate admin requests")
		}
		adminSecret, err := keyring.Resolve(*adminKey)
		if err != nil {
			return err
		}
		controlHandler, err := server.NewHandler(srv, keyStore, adminSecret)
		if err != nil {
			return fmt.Errorf("build control handler: %w", err)
		}
		handlers = append(handlers, serveHTTP(ctx, errCh, *adminAddr, controlHandler, nil))
	}
	switch {
	case *httpsAddr == "":
		handlers = append(handlers, serveHTTP(ctx, errCh, *httpAddr, srv.Handler(), nil))
	case *acmeEmail != "":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      *acmeEmail,
			Cache:      autocert.DirCache(*dataDir),
			HostPolicy: hostPolicy(*domain),
		}
		tlsCfg := m.TLSConfig()
		tlsCfg.MinVersion = tls.VersionTLS12
		handlers = append(handlers, serveHTTP(ctx, errCh, *httpsAddr, srv.Handler(), tlsCfg))
		if *httpAddr != "" {
			redirect := func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			}
			handlers = append(handlers, serveHTTP(ctx, errCh, *httpAddr, m.HTTPHandler(http.HandlerFunc(redirect)), nil))
		}
	default:
		handlers = append(handlers, serveHTTP(ctx, errCh, *httpsAddr, srv.Handler(), staticTLS))
		if *httpAddr != "" {
			redirect := func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			}
			handlers = append(handlers, serveHTTP(ctx, errCh, *httpAddr, http.HandlerFunc(redirect), nil))
		}
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range handlers {
		_ = s.Shutdown(shutdownCtx)
	}
	if err := srv.Close(); err != nil {
		return err
	}
	return nil
}

func serveControl(ctx context.Context, errCh chan<- error, addr string, tlsCfg *tls.Config, srv *relay.Server) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		errCh <- fmt.Errorf("control listen: %w", err)
		return
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go srv.HandleAgent(conn)
	}
}

func serveHTTP(ctx context.Context, errCh chan<- error, addr string, handler http.Handler, tlsCfg *tls.Config) *http.Server {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		errCh <- fmt.Errorf("http listen on %s: %w", addr, err)
		return nil
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	s := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http serve on %s: %w", addr, err)
		}
	}()
	return s
}

func hostPolicy(base string) func(ctx context.Context, host string) error {
	return func(_ context.Context, host string) error {
		if host == base || strings.HasSuffix(host, "."+base) {
			return nil
		}
		return fmt.Errorf("acme: host %q not allowed", host)
	}
}

func parsePortRange(s string) (int, int, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, err
	}
	if start <= 0 || end < start || end > 65535 {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	return start, end, nil
}

func buildLogger(verbose, jsonOut bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if jsonOut {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
