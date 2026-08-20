package main

import (
	"bytes"
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kproxy/internal/admin"
	"kproxy/internal/config"
	"kproxy/internal/protocol"
	"kproxy/internal/store"
)

func TestKeySubcommands(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(admin.NewHandler(st, "boot-secret"))
	defer ts.Close()

	var out, errOut bytes.Buffer

	if err := runKey([]string{"create", "--name", "ci", "--ttl", "30d", "--admin-url", ts.URL, "--admin-key", "boot-secret"}, &out, &errOut); err != nil {
		t.Fatalf("create: %v (stderr: %s)", err, errOut.String())
	}
	if !strings.Contains(out.String(), "Secret:  kproxy_") {
		t.Fatalf("create output missing secret: %q", out.String())
	}
	secret := strings.TrimSpace(strings.Split(strings.Split(out.String(), "Secret:  ")[1], "\n")[0])
	if _, err := st.ValidateKey(secret); err != nil {
		t.Fatalf("created secret did not validate: %v", err)
	}

	var keyID string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "  ID:      ") {
			keyID = strings.TrimSpace(strings.TrimPrefix(line, "  ID:      "))
		}
	}

	out.Reset()
	errOut.Reset()
	if err := runKey([]string{"list", "--admin-url", ts.URL, "--admin-key", "boot-secret"}, &out, &errOut); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out.String(), keyID) {
		t.Fatalf("list output missing key: %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	if err := runKey([]string{"revoke", keyID, "--admin-url", ts.URL, "--admin-key", "boot-secret"}, &out, &errOut); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.ValidateKey(secret); err == nil {
		t.Fatal("revoked secret still validates")
	}

	out.Reset()
	errOut.Reset()
	err = runKey([]string{"create", "--name", "x", "--admin-url", ts.URL, "--admin-key", "wrong"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("create with bad admin key error = %v, want unauthorized", err)
	}
}

func TestKeySubcommandRequiresAdminKey(t *testing.T) {
	os.Unsetenv("KPROXY_ADMIN_KEY")
	var out, errOut bytes.Buffer
	err := runKey([]string{"list"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "admin-key") {
		t.Fatalf("error = %v, want admin-key required", err)
	}
}

func TestReorderFlagArgs(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	subdomain := fs.String("subdomain", "", "")
	verbose := fs.Bool("verbose", false, "")

	reordered := reorderFlagArgs(fs, []string{"8082", "--subdomain", "myapp", "--verbose", "extra"})
	expected := []string{"--subdomain", "myapp", "--verbose", "8082", "extra"}
	if !reflect.DeepEqual(reordered, expected) {
		t.Fatalf("reordered = %v, want %v", reordered, expected)
	}

	if err := fs.Parse(reordered); err != nil {
		t.Fatal(err)
	}
	if *subdomain != "myapp" || !*verbose {
		t.Fatalf("parsed subdomain=%q verbose=%v", *subdomain, *verbose)
	}
	if fs.Arg(0) != "8082" || fs.Arg(1) != "extra" {
		t.Fatalf("positional = %v", fs.Args())
	}
}

func TestReorderFlagArgsEqualsForm(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	domain := fs.String("domain", "", "")

	reordered := reorderFlagArgs(fs, []string{"8082", "--domain=app.example.com"})
	if err := fs.Parse(reordered); err != nil {
		t.Fatal(err)
	}
	if *domain != "app.example.com" {
		t.Fatalf("domain = %q", *domain)
	}
	if fs.Arg(0) != "8082" {
		t.Fatalf("positional = %v", fs.Args())
	}
}

func TestSpecsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnels.json")
	content := `{
	  "tunnels": [
	    {"proto": "http", "local": "8082", "subdomain": "api"},
	    {"proto": "tcp", "local": "127.0.0.1:3306", "port": 2200},
	    {"proto": "http", "local": "0.0.0.0:9090", "domain": "app.client.com", "basic_auth": "user:pass", "ip_allow": ["10.0.0.0/8"], "ip_deny": ["10.0.0.5"], "max_request_size": "1mb", "request_timeout": "30s"}
	  ]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	tf, err := config.LoadTunnelFile(path)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := specsFromFile(tf)
	if err != nil {
		t.Fatal(err)
	}

	want := []protocol.TunnelSpec{
		{ID: "t1", Proto: "http", Local: "127.0.0.1:8082", Subdomain: "api"},
		{ID: "t2", Proto: "tcp", Local: "127.0.0.1:3306", Port: 2200},
		{ID: "t3", Proto: "http", Local: "0.0.0.0:9090", Domain: "app.client.com", BasicAuth: "user:pass", IPAllow: []string{"10.0.0.0/8"}, IPDeny: []string{"10.0.0.5"}, MaxRequestSize: "1mb", RequestTimeout: "30s"},
	}
	if !reflect.DeepEqual(specs, want) {
		t.Fatalf("specs = %+v\nwant %+v", specs, want)
	}
}

func TestSpecsFromFileErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		path := filepath.Join(dir, "t.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	cases := []struct {
		name    string
		content string
	}{
		{"no tunnels", `{"tunnels": []}`},
		{"bad proto", `{"tunnels": [{"proto": "udp", "local": "8082"}]}`},
		{"bad local", `{"tunnels": [{"proto": "http", "local": "not-a-port"}]}`},
		{"bad port", `{"tunnels": [{"proto": "tcp", "local": "8082", "port": 99999}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tf, err := config.LoadTunnelFile(write(tc.content))
			if err != nil {
				if tc.name == "no tunnels" {
					return
				}
				t.Fatalf("unexpected load error: %v", err)
			}
			if _, err := specsFromFile(tf); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
