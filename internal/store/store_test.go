package store

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateAndValidate(t *testing.T) {
	s := open(t)
	info, secret, err := s.Create("alice", 0, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == "" || info.Name != "alice" || info.Revoked {
		t.Fatalf("unexpected key info: %+v", info)
	}
	if !strings.HasPrefix(secret, "kproxy_") {
		t.Fatalf("secret = %q, want kproxy_ prefix", secret)
	}
	if _, err := s.ValidateKey(secret); err != nil {
		t.Fatalf("validate created key: %v", err)
	}
	if _, err := s.ValidateKey("wrong"); err == nil {
		t.Fatal("validate of wrong secret succeeded")
	}
}

func TestRevoke(t *testing.T) {
	s := open(t)
	info, secret, _ := s.Create("bob", 0, Limits{})
	if err := s.Revoke(info.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateKey(secret); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("validate revoked key error = %v, want revoked", err)
	}
	list := s.List()
	if len(list) != 1 || !list[0].Revoked {
		t.Fatalf("list = %+v, want one revoked key", list)
	}
	if err := s.Revoke(info.ID); err == nil {
		t.Fatal("revoking twice should error")
	}
	if err := s.Revoke("k_doesnotexist"); err == nil {
		t.Fatal("revoking unknown key should error")
	}
}

func TestExpiry(t *testing.T) {
	s := open(t)
	_, secret, _ := s.Create("carol", 50*time.Millisecond, Limits{})
	if _, err := s.ValidateKey(secret); err != nil {
		t.Fatalf("validate before expiry: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := s.ValidateKey(secret); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("validate after expiry error = %v, want expired", err)
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, secret, _ := s1.Create("dave", 0, Limits{})

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.ValidateKey(secret); err != nil {
		t.Fatalf("validate after reload: %v", err)
	}
	list := s2.List()
	if len(list) != 1 || list[0].ID != info.ID {
		t.Fatalf("list after reload = %+v", list)
	}
}

func TestListNewestFirst(t *testing.T) {
	s := open(t)
	first, _, _ := s.Create("one", 0, Limits{})
	time.Sleep(2 * time.Millisecond)
	second, _, _ := s.Create("two", 0, Limits{})
	list := s.List()
	if len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID {
		t.Fatalf("list order = %+v", list)
	}
}

func TestSecretsNeverStored(t *testing.T) {
	s := open(t)
	_, secret, _ := s.Create("eve", 0, Limits{})
	raw, err := readFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("plaintext secret leaked into the store file")
	}
}

func TestLimitsRoundTrip(t *testing.T) {
	s := open(t)
	limits := Limits{
		RequestsPerSec:    50,
		BandwidthPerSec:   1 << 20,
		AllowedSubdomains: []string{"api", "staging"},
	}
	info, secret, err := s.Create("limited", 0, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(info.Limits, limits) {
		t.Fatalf("info.Limits = %+v, want %+v", info.Limits, limits)
	}

	ident, err := s.ValidateKey(secret)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if ident.ID != info.ID || !reflect.DeepEqual(ident.Limits, limits) {
		t.Fatalf("identity = %+v, want ID %s with limits %+v", ident, info.ID, limits)
	}

	raw, err := readFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "requests_per_sec") {
		t.Fatal("limits not persisted to the store file")
	}
}
