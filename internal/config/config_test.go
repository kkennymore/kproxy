package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.json")

	in := AgentConfig{ServerURL: "https://relay.example.com:55555", APIKey: "supersecret"}
	if err := SaveAgentAt(in, path); err != nil {
		t.Fatalf("save: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %o, want 600", fi.Mode().Perm())
	}

	out, err := LoadAgentAt(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v != %+v", out, in)
	}
}

func TestLoadAgentMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	out, err := LoadAgentAt(filepath.Join(dir, "does-not-exist.json"))
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if out.ServerURL != "" || out.APIKey != "" {
		t.Fatalf("expected empty config, got %+v", out)
	}
}
