// Command kproxy is the agent CLI. It opens HTTP or TCP tunnels to a kproxyd
// relay server and prints the public URLs assigned by the server.
//
// Usage:
//
//	kproxy http 8082 [--subdomain myapp] [--domain app.example.com]
//	kproxy tcp 3306 [--port 2200]
//	kproxy tunnels -f tunnels.json
//	kproxy --version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kproxy/internal/admin"
	"kproxy/internal/agent"
	"kproxy/internal/config"
	"kproxy/internal/keyring"
	"kproxy/internal/protocol"
	"kproxy/internal/store"
	"kproxy/internal/version"
)

const defaultServer = "http://localhost:55555"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "kproxy:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errors.New("missing command")
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return nil
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "kproxy %s\n", version.String())
		return nil
	case "http", "tcp":
		return runTunnel(args[0], args[1:], stdout, stderr)
	case "tunnels":
		return runTunnels(args[1:], stdout, stderr)
	case "key":
		return runKey(args[1:], stdout, stderr)
	case "keyring":
		return runKeyring(args[1:], stdout, stderr)
	case "domain":
		return runDomain(args[1:], stdout, stderr)
	case "requests":
		return runRequests(args[1:], stdout, stderr)
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `kproxy - expose local services through a public relay without port forwarding

Usage:
  kproxy http <port> [flags]     expose an HTTP service
  kproxy tcp <port>  [flags]     expose a raw TCP service
  kproxy tunnels -f FILE [flags] expose several tunnels from one process
  kproxy key <cmd> [flags]       manage api keys on the relay (create/revoke/list)
  kproxy keyring <cmd> [flags]   manage secrets in the OS keyring (set/get/rm/list)
  kproxy domain verify-token HOST [flags]  get the DNS TXT token for a custom domain
  kproxy requests [flags]       show recent proxied requests from the relay log

Tunnel flags:
  --subdomain NAME     request a custom subdomain (default: random)
  --domain HOST        expose on a custom domain you control
  --local-host HOST    local host to forward to (default 127.0.0.1)
  --port PORT          request a specific public port (tcp only)
  --basic-auth USER:PASS  protect an http tunnel with HTTP Basic auth
  --ip-allow 1.2.3.4,10.0.0.0/8  allow only these client IPs/CIDRs
  --ip-deny  1.2.3.4,10.0.0.0/8  deny these client IPs/CIDRs
  --max-request-size 1mb   cap http request bodies (0 = unlimited)
  --request-timeout 30s    bound how long a request may take (0 = none)
  --server URL       relay server endpoint (default `+defaultServer+`)
  --api-key KEY      api key for this relay (prompts on first run); use
                     keyring:NAME to read it from the OS keyring
  --config PATH      config file to read/write (default platform config)
  --verbose          verbose logging
  --json             json log output

Key flags (key subcommands):
  --admin-url URL    admin api endpoint (default http://127.0.0.1:55556)
  --admin-key KEY    admin secret (env KPROXY_ADMIN_KEY); use keyring:NAME
                     to read it from the OS keyring
  --name NAME        label for a new key
  --ttl DURATION     key lifetime, e.g. 24h, 7d, 30d (default: never)

Keyring subcommands:
  kproxy keyring set NAME [VALUE]  store a secret (reads stdin if VALUE omitted)
  kproxy keyring get NAME          print a stored secret
  kproxy keyring rm NAME           remove a stored secret
  kproxy keyring list              list stored names

Tunnel file format (JSON):
  {
    "server_url": "https://relay.example.com:55555",
    "api_key": "secret",
    "tunnels": [
      {"proto": "http", "local": "8082", "subdomain": "api"},
      {"proto": "tcp",  "local": "127.0.0.1:3306", "port": 2200}
    ]
  }
`)
}

func runTunnel(proto string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("kproxy "+proto, flag.ContinueOnError)
	fs.SetOutput(stderr)
	subdomain := fs.String("subdomain", "", "")
	domain := fs.String("domain", "", "")
	localHost := fs.String("local-host", "127.0.0.1", "")
	portPinned := fs.Int("port", 0, "")
	basicAuth := fs.String("basic-auth", "", "")
	ipAllow := fs.String("ip-allow", "", "")
	ipDeny := fs.String("ip-deny", "", "")
	maxRequestSize := fs.String("max-request-size", "", "")
	requestTimeout := fs.String("request-timeout", "", "")
	serverURL := fs.String("server", "", "")
	apiKey := fs.String("api-key", "", "")
	configPath := fs.String("config", "", "")
	verbose := fs.Bool("verbose", false, "")
	jsonLog := fs.Bool("json", false, "")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("a target port is required")
	}
	port := fs.Arg(0)
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("invalid target port %q", port)
	}
	if proto == protocol.ProtoHTTP && *portPinned != 0 {
		return errors.New("--port only applies to tcp tunnels")
	}
	if *portPinned < 0 || *portPinned > 65535 {
		return fmt.Errorf("invalid public port %d", *portPinned)
	}
	opts, err := validateTunnelOptions(proto, *basicAuth, *ipAllow, *ipDeny, *maxRequestSize, *requestTimeout)
	if err != nil {
		return err
	}

	creds, err := resolveCreds(*serverURL, *apiKey, *configPath, "", "", stdout)
	if err != nil {
		return err
	}

	spec := protocol.TunnelSpec{
		ID:             "main",
		Proto:          proto,
		Local:          *localHost + ":" + port,
		Subdomain:      *subdomain,
		Domain:         *domain,
		Port:           *portPinned,
		BasicAuth:      opts.basicAuth,
		IPAllow:        opts.ipAllow,
		IPDeny:         opts.ipDeny,
		MaxRequestSize: opts.maxRequestSize,
		RequestTimeout: opts.requestTimeout,
	}
	return startAgent(creds, []protocol.TunnelSpec{spec}, *verbose, *jsonLog, stdout, stderr)
}

// tunnelOptions carries the validated per-tunnel security options.
type tunnelOptions struct {
	basicAuth      string
	ipAllow        []string
	ipDeny         []string
	maxRequestSize string
	requestTimeout string
}

// validateTunnelOptions parses and validates per-tunnel flags so bad input
// fails fast instead of round-tripping to the server.
func validateTunnelOptions(proto, basicAuth, ipAllow, ipDeny, maxRequestSize, requestTimeout string) (tunnelOptions, error) {
	opts := tunnelOptions{
		basicAuth:      basicAuth,
		maxRequestSize: maxRequestSize,
		requestTimeout: requestTimeout,
	}
	if proto == protocol.ProtoHTTP {
		if opts.basicAuth != "" && !strings.Contains(opts.basicAuth, ":") {
			return opts, errors.New("--basic-auth must be in user:pass form")
		}
		if opts.maxRequestSize != "" {
			if _, err := admin.ParseSize(opts.maxRequestSize); err != nil {
				return opts, err
			}
		}
		if opts.requestTimeout != "" {
			if _, err := time.ParseDuration(opts.requestTimeout); err != nil {
				return opts, err
			}
		}
	} else {
		if opts.basicAuth != "" {
			return opts, errors.New("--basic-auth only applies to http tunnels")
		}
		if opts.maxRequestSize != "" {
			return opts, errors.New("--max-request-size only applies to http tunnels")
		}
		if opts.requestTimeout != "" {
			return opts, errors.New("--request-timeout only applies to http tunnels")
		}
	}
	for _, items := range []struct {
		src, flag string
		dst       *[]string
	}{
		{ipAllow, "ip-allow", &opts.ipAllow},
		{ipDeny, "ip-deny", &opts.ipDeny},
	} {
		for _, item := range strings.Split(items.src, ",") {
			if item = strings.TrimSpace(item); item == "" {
				continue
			}
			if err := validateIPNet(item); err != nil {
				return opts, fmt.Errorf("--%s: %w", items.flag, err)
			}
			*items.dst = append(*items.dst, item)
		}
	}
	return opts, nil
}

func validateIPNet(s string) error {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid ip or cidr %q", s)
	}
	return nil
}

func runTunnels(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("kproxy tunnels", flag.ContinueOnError)
	fs.SetOutput(stderr)
	filePath := ""
	fs.StringVar(&filePath, "file", "", "")
	fs.StringVar(&filePath, "f", "", "")
	serverURL := fs.String("server", "", "")
	apiKey := fs.String("api-key", "", "")
	configPath := fs.String("config", "", "")
	verbose := fs.Bool("verbose", false, "")
	jsonLog := fs.Bool("json", false, "")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return err
	}
	if filePath == "" {
		fs.Usage()
		return errors.New("-f FILE is required")
	}

	tf, err := config.LoadTunnelFile(filePath)
	if err != nil {
		return fmt.Errorf("load tunnel file: %w", err)
	}
	specs, err := specsFromFile(tf)
	if err != nil {
		return err
	}

	creds, err := resolveCreds(*serverURL, *apiKey, *configPath, tf.ServerURL, tf.APIKey, stdout)
	if err != nil {
		return err
	}
	return startAgent(creds, specs, *verbose, *jsonLog, stdout, stderr)
}

// resolveCreds applies the flag > env > config file > tunnel-file > default
// precedence, prompting for and persisting the api key on first use.
func resolveCreds(serverFlag, apiKeyFlag, configPath, fileServer, fileKey string, stdout io.Writer) (creds, error) {
	server := serverFlag
	key := apiKeyFlag
	if server == "" {
		server = os.Getenv("KPROXY_SERVER")
	}
	if key == "" {
		key = os.Getenv("KPROXY_API_KEY")
	}

	cfg, err := config.LoadAgentAt(configPath)
	if err != nil {
		return creds{}, fmt.Errorf("load config: %w", err)
	}

	if server == "" {
		switch {
		case cfg.ServerURL != "":
			server = cfg.ServerURL
		case fileServer != "":
			server = fileServer
		default:
			server = defaultServer
		}
	}
	if key == "" {
		switch {
		case cfg.APIKey != "":
			key = cfg.APIKey
		case fileKey != "":
			key = fileKey
		}
	}

	if key == "" {
		stdin := bufio.NewReader(os.Stdin)
		key, err = promptAPIKey(stdin, stdout, server)
		if err != nil {
			return creds{}, err
		}
		cfg.ServerURL = server
		cfg.APIKey = key
		if err := config.SaveAgentAt(cfg, configPath); err != nil {
			return creds{}, fmt.Errorf("save config: %w", err)
		}
		fmt.Fprintln(stdout, "credentials saved.")
	}
	resolved, err := keyring.Resolve(key)
	if err != nil {
		return creds{}, err
	}
	return creds{server: server, apiKey: resolved}, nil
}

func startAgent(c creds, specs []protocol.TunnelSpec, verbose, jsonOut bool, stdout, stderr io.Writer) error {
	logger := buildLogger(verbose, jsonOut, stderr)
	ag := agent.New(agent.Config{
		ServerURL: c.server,
		APIKey:    c.apiKey,
		Tunnels:   specs,
		OnWelcome: func(w protocol.Welcome) {
			printWelcome(stdout, w)
		},
		OnAssigned: func(assigns []protocol.TunnelAssign) {
			for _, a := range assigns {
				fmt.Fprintf(stdout, "  %s (reassigned)\n", a.PublicURL)
			}
		},
		Logger: logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := ag.Run(ctx); err != nil {
		var rejected *agent.ServerRejected
		if errors.As(err, &rejected) {
			return fmt.Errorf("%w\nhint: this api key was rejected by the server; create one with `kproxy key create --admin-key <secret>` or ask your operator", err)
		}
		return err
	}
	fmt.Fprintln(stdout, "kproxy stopped.")
	return nil
}

func specsFromFile(tf config.TunnelFile) ([]protocol.TunnelSpec, error) {
	var specs []protocol.TunnelSpec
	for i, e := range tf.Tunnels {
		switch e.Proto {
		case protocol.ProtoHTTP, protocol.ProtoTCP:
		default:
			return nil, fmt.Errorf("tunnel %d: unsupported proto %q", i+1, e.Proto)
		}
		local := e.Local
		if !strings.Contains(local, ":") {
			if _, err := strconv.Atoi(local); err != nil {
				return nil, fmt.Errorf("tunnel %d: local %q must be host:port or a port number", i+1, e.Local)
			}
			local = "127.0.0.1:" + local
		}
		if e.Port < 0 || e.Port > 65535 {
			return nil, fmt.Errorf("tunnel %d: invalid public port %d", i+1, e.Port)
		}
		specs = append(specs, protocol.TunnelSpec{
			ID:             fmt.Sprintf("t%d", i+1),
			Proto:          e.Proto,
			Local:          local,
			Subdomain:      e.Subdomain,
			Domain:         e.Domain,
			Port:           e.Port,
			BasicAuth:      e.BasicAuth,
			IPAllow:        e.IPAllow,
			IPDeny:         e.IPDeny,
			MaxRequestSize: e.MaxRequestSize,
			RequestTimeout: e.RequestTimeout,
		})
	}
	return specs, nil
}

type creds struct {
	server string
	apiKey string
}

const defaultAdminURL = "http://127.0.0.1:55556"

func runKey(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kproxy key create|revoke|list [flags]")
		return errors.New("missing key subcommand")
	}
	switch args[0] {
	case "create":
		return runKeyCreate(args[1:], stdout, stderr)
	case "revoke":
		return runKeyRevoke(args[1:], stdout, stderr)
	case "list":
		return runKeyList(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown key subcommand %q", args[0])
	}
}

func runKeyCreate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("kproxy key create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "label for the new key")
	ttl := fs.String("ttl", "", "key lifetime, e.g. 24h, 7d, 30d (default: never)")
	rate := fs.Int("rate", 0, "max HTTP requests per second (0 = unlimited)")
	bandwidth := fs.String("bandwidth", "", "max tunnel throughput, e.g. 1mb, 512kb (0 = unlimited)")
	subdomains := fs.String("subdomain", "", "comma-separated allowed subdomains (empty = any)")
	adminURL := fs.String("admin-url", defaultAdminURL, "admin api endpoint")
	adminKey := fs.String("admin-key", "", "admin secret (env KPROXY_ADMIN_KEY)")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("unexpected arguments")
	}
	key, err := resolveAdminKey(*adminKey)
	if err != nil {
		return err
	}
	if *rate < 0 {
		return errors.New("--rate must be >= 0")
	}
	if _, err := admin.ParseSize(*bandwidth); err != nil {
		return err
	}
	var subs []string
	for _, s := range strings.Split(*subdomains, ",") {
		if s = strings.TrimSpace(s); s != "" {
			subs = append(subs, strings.ToLower(s))
		}
	}
	info, secret, err := admin.CreateKey(*adminURL, key, admin.CreateOptions{
		Name:       *name,
		TTL:        *ttl,
		Rate:       *rate,
		Bandwidth:  *bandwidth,
		Subdomains: subs,
	})
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}
	fmt.Fprintf(stdout, "Created key:\n")
	fmt.Fprintf(stdout, "  ID:      %s\n", info.ID)
	fmt.Fprintf(stdout, "  Name:    %s\n", info.Name)
	if info.ExpiresAt.IsZero() {
		fmt.Fprintf(stdout, "  Expires: never\n")
	} else {
		fmt.Fprintf(stdout, "  Expires: %s\n", info.ExpiresAt.Local().Format(time.RFC3339))
	}
	fmt.Fprintf(stdout, "  Secret:  %s\n", secret)
	if !info.Limits.IsZero() {
		fmt.Fprintf(stdout, "  Limits:  %s\n", describeLimits(info.Limits))
	}
	fmt.Fprintln(stdout, "Save this secret now - it is shown only once.")
	return nil
}

func describeLimits(l store.Limits) string {
	var parts []string
	if l.RequestsPerSec > 0 {
		parts = append(parts, fmt.Sprintf("%d req/s", l.RequestsPerSec))
	}
	if l.BandwidthPerSec > 0 {
		parts = append(parts, fmt.Sprintf("%d B/s bandwidth", l.BandwidthPerSec))
	}
	if len(l.AllowedSubdomains) > 0 {
		parts = append(parts, "subdomains: "+strings.Join(l.AllowedSubdomains, ","))
	}
	return strings.Join(parts, ", ")
}

func runKeyRevoke(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("kproxy key revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	adminURL := fs.String("admin-url", defaultAdminURL, "admin api endpoint")
	adminKey := fs.String("admin-key", "", "admin secret (env KPROXY_ADMIN_KEY)")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("a key ID is required")
	}
	key, err := resolveAdminKey(*adminKey)
	if err != nil {
		return err
	}
	if err := admin.RevokeKey(*adminURL, key, fs.Arg(0)); err != nil {
		return fmt.Errorf("revoke key: %w", err)
	}
	fmt.Fprintf(stdout, "Revoked key %s.\n", fs.Arg(0))
	return nil
}

func runKeyList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("kproxy key list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	adminURL := fs.String("admin-url", defaultAdminURL, "admin api endpoint")
	adminKey := fs.String("admin-key", "", "admin secret (env KPROXY_ADMIN_KEY)")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("unexpected arguments")
	}
	key, err := resolveAdminKey(*adminKey)
	if err != nil {
		return err
	}
	keys, err := admin.ListKeys(*adminURL, key)
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	fmt.Fprintf(stdout, "%-14s %-20s %-24s %s\n", "ID", "NAME", "EXPIRES", "REVOKED")
	for _, k := range keys {
		exp := "never"
		if !k.ExpiresAt.IsZero() {
			exp = k.ExpiresAt.Local().Format(time.RFC3339)
		}
		fmt.Fprintf(stdout, "%-14s %-20s %-24s %t\n", k.ID, k.Name, exp, k.Revoked)
	}
	return nil
}

// resolveAdminKey applies the flag > env precedence for the admin secret and
// expands a keyring:NAME reference.
func resolveAdminKey(flagVal string) (string, error) {
	key := flagVal
	if key == "" {
		key = os.Getenv("KPROXY_ADMIN_KEY")
	}
	if key == "" {
		return "", errors.New("--admin-key is required (or set KPROXY_ADMIN_KEY)")
	}
	return keyring.Resolve(key)
}

// runKeyring dispatches the keyring management subcommands.
func runKeyring(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kproxy keyring set|get|rm|list [flags]")
		return errors.New("missing keyring subcommand")
	}
	switch args[0] {
	case "set":
		return runKeyringSet(args[1:], stdout, stderr)
	case "get":
		return runKeyringGet(args[1:], stdout, stderr)
	case "rm", "delete":
		return runKeyringRm(args[1:], stdout, stderr)
	case "list":
		return runKeyringList(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown keyring subcommand %q", args[0])
	}
}

func runKeyringSet(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(stderr, "usage: kproxy keyring set NAME [VALUE]")
		return errors.New("NAME is required")
	}
	name := args[0]
	value := ""
	if len(args) == 2 {
		value = args[1]
	} else {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read value from stdin: %w", err)
		}
		value = strings.TrimSpace(string(b))
	}
	if value == "" {
		return errors.New("value cannot be empty")
	}
	kr, err := keyring.Open()
	if err != nil {
		return err
	}
	if err := kr.Set(name, value); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "stored %q in the keyring (%s)\n", name, kr.Path())
	return nil
}

func runKeyringGet(args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: kproxy keyring get NAME")
		return errors.New("NAME is required")
	}
	kr, err := keyring.Open()
	if err != nil {
		return err
	}
	v, ok, err := kr.Get(args[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("keyring has no entry %q", args[0])
	}
	fmt.Fprintln(stdout, v)
	return nil
}

func runKeyringRm(args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: kproxy keyring rm NAME")
		return errors.New("NAME is required")
	}
	kr, err := keyring.Open()
	if err != nil {
		return err
	}
	if err := kr.Delete(args[0]); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "removed %q from the keyring\n", args[0])
	return nil
}

func runKeyringList(args []string, stdout, stderr io.Writer) error {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: kproxy keyring list")
		return errors.New("unexpected arguments")
	}
	kr, err := keyring.Open()
	if err != nil {
		return err
	}
	names, err := kr.List()
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Fprintln(stdout, n)
	}
	return nil
}

func promptAPIKey(r *bufio.Reader, w io.Writer, server string) (string, error) {
	fmt.Fprintf(w, "kproxy has no api key for %s.\n", server)
	fmt.Fprintf(w, "Ask the server operator for a key, then enter it here: ")
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read api key: %w", err)
	}
	key := strings.TrimSpace(line)
	if key == "" {
		return "", errors.New("api key cannot be empty")
	}
	return key, nil
}

// runDomain prints the DNS TXT verification token an operator sets at
// _kproxy.<host> to prove they control a custom domain.
func runDomain(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kproxy domain verify-token HOST [flags]")
		return errors.New("missing domain subcommand")
	}
	switch args[0] {
	case "verify-token":
		return runDomainToken(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown domain subcommand %q", args[0])
	}
}

func runDomainToken(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("kproxy domain verify-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	adminURL := fs.String("admin-url", defaultAdminURL, "admin api endpoint")
	adminKey := fs.String("admin-key", "", "admin secret (env KPROXY_ADMIN_KEY)")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("a host is required")
	}
	key, err := resolveAdminKey(*adminKey)
	if err != nil {
		return err
	}
	host := fs.Arg(0)
	token, err := admin.DomainToken(*adminURL, key, host)
	if err != nil {
		return fmt.Errorf("get verification token: %w", err)
	}
	fmt.Fprintf(stdout, "Set a DNS TXT record at _kproxy.%s with value:\n", host)
	fmt.Fprintf(stdout, "  %s\n", token)
	return nil
}

func printWelcome(w io.Writer, wel protocol.Welcome) {
	fmt.Fprintf(w, "Tunnel online on %s\n", wel.Server)
	for _, t := range wel.Tunnels {
		fmt.Fprintf(w, "  %s\n", t.PublicURL)
	}
}

// runRequests prints recent proxied requests from the relay's bounded replay
// log, newest first.
func runRequests(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("kproxy requests", flag.ContinueOnError)
	fs.SetOutput(stderr)
	limit := fs.Int("limit", 50, "max requests to show (0 = all retained)")
	adminURL := fs.String("admin-url", defaultAdminURL, "admin api endpoint")
	adminKey := fs.String("admin-key", "", "admin secret (env KPROXY_ADMIN_KEY)")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("unexpected arguments")
	}
	if *limit < 0 {
		return errors.New("--limit must be >= 0")
	}
	key, err := resolveAdminKey(*adminKey)
	if err != nil {
		return err
	}
	reqs, err := admin.ListRequests(*adminURL, key, *limit)
	if err != nil {
		return fmt.Errorf("list requests: %w", err)
	}
	fmt.Fprintf(stdout, "%-24s %-6s %-20s %-6s %8s %8s %s\n",
		"TIME", "METHOD", "HOST", "STATUS", "DURATION", "BYTES", "PATH")
	for _, r := range reqs {
		fmt.Fprintf(stdout, "%-24s %-6s %-20s %-6d %8s %8d %s\n",
			r.Time.Local().Format("2006-01-02 15:04:05"),
			r.Method, r.Host, r.Status,
			r.Duration.Round(time.Millisecond).String(), r.Bytes, r.Path)
	}
	return nil
}

func buildLogger(verbose, jsonOut bool, w io.Writer) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if jsonOut {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// reorderFlagArgs moves all flags ahead of positional arguments so that the
// stdlib flag package (which stops at the first non-flag token) can parse
// invocations like "kproxy http 8082 --server host".
func reorderFlagArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			flags = append(flags, a)
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			flags = append(flags, a)
			continue
		}
		if _, isBool := f.Value.(interface{ IsBoolFlag() bool }); isBool {
			flags = append(flags, a)
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, a, args[i+1])
			i++
		} else {
			flags = append(flags, a)
		}
	}
	return append(flags, positional...)
}
