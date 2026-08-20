package keyring

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRingRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	r, err := OpenAt(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok, _ := r.Get("missing"); ok {
		t.Fatal("unexpected entry for missing name")
	}
	if err := r.Set("relay-admin", "s3cret!"); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("agent", "k-abc123"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := r.Get("relay-admin")
	if err != nil || !ok || got != "s3cret!" {
		t.Fatalf("Get = %q, %v, %v; want s3cret!", got, ok, err)
	}
	names, err := r.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "agent" || names[1] != "relay-admin" {
		t.Fatalf("List = %v", names)
	}

	// Persistence: reopen and read again.
	r2, err := OpenAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := r2.Get("agent"); !ok || got != "k-abc123" {
		t.Fatalf("reopened Get = %q, %v", got, ok)
	}

	if err := r2.Delete("agent"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r2.Get("agent"); ok {
		t.Fatal("entry not deleted")
	}
}

func TestResolve(t *testing.T) {
	if got, err := Resolve("plain-value"); err != nil || got != "plain-value" {
		t.Fatalf("Resolve(plain) = %q, %v", got, err)
	}
	dir := t.TempDir()
	r, err := OpenAt(filepath.Join(dir, "kproxy", "keyring.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Set("mykey", "secret-from-ring"); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAt(r, "keyring:mykey")
	if err != nil || got != "secret-from-ring" {
		t.Fatalf("resolveAt(keyring:mykey) = %q, %v", got, err)
	}
	if _, err := resolveAt(r, "keyring:nope"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("resolveAt(missing) err = %v", err)
	}
}

func TestInvalidName(t *testing.T) {
	r, err := OpenAt(filepath.Join(t.TempDir(), "kr.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Set("", "x"); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := r.Set("keyring:loop", "x"); err == nil {
		t.Fatal("keyring: prefix name accepted")
	}
}
