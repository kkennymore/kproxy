// Package keyring stores secrets (API keys, admin keys) in an OS-backed
// store. On Windows, values are protected with DPAPI (local-machine scope)
// before they are written to disk. On macOS and Linux there is no pure-Go
// keychain access without cgo, so the fallback is a JSON file with
// owner-only permissions.
package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ring is a named-secret store backed by a single file.
type Ring struct {
	path string
}

// DefaultPath returns the platform-appropriate keyring file path.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "kproxy", "keyring.json"), nil
}

// Open opens (creating if needed) the keyring at the default path.
func Open() (*Ring, error) {
	p, err := DefaultPath()
	if err != nil {
		return nil, err
	}
	return OpenAt(p)
}

// OpenAt opens the keyring at a specific file path, creating it on first use.
func OpenAt(path string) (*Ring, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return &Ring{path: path}, nil
}

// Path returns the underlying file path.
func (r *Ring) Path() string { return r.path }

type entries map[string]string

func (r *Ring) load() (entries, error) {
	b, err := os.ReadFile(r.path)
	if err != nil {
		return nil, err
	}
	var m entries
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (r *Ring) save(m entries) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, b, 0o600)
}

func validateName(name string) error {
	if name == "" {
		return errors.New("keyring name cannot be empty")
	}
	if strings.HasPrefix(name, "keyring:") {
		return errors.New("keyring names must not start with \"keyring:\"")
	}
	return nil
}

// Set stores a secret under name, replacing any existing value.
func (r *Ring) Set(name, value string) error {
	if err := validateName(name); err != nil {
		return err
	}
	m, err := r.load()
	if err != nil {
		return err
	}
	protected, err := encryptValue([]byte(value))
	if err != nil {
		return err
	}
	m[name] = protected
	return r.save(m)
}

// Get returns the secret stored under name.
func (r *Ring) Get(name string) (string, bool, error) {
	m, err := r.load()
	if err != nil {
		return "", false, err
	}
	protected, ok := m[name]
	if !ok {
		return "", false, nil
	}
	plain, err := decryptValue(protected)
	if err != nil {
		return "", true, err
	}
	return string(plain), true, nil
}

// Delete removes the secret stored under name.
func (r *Ring) Delete(name string) error {
	m, err := r.load()
	if err != nil {
		return err
	}
	if _, ok := m[name]; !ok {
		return nil
	}
	delete(m, name)
	return r.save(m)
}

// List returns all stored names in sorted order.
func (r *Ring) List() ([]string, error) {
	m, err := r.load()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// Resolve expands a "keyring:NAME" reference to its stored secret. Values
// without the prefix are returned unchanged. An unknown name is an error.
func Resolve(value string) (string, error) {
	if !strings.HasPrefix(value, "keyring:") {
		return value, nil
	}
	kr, err := Open()
	if err != nil {
		return "", err
	}
	return resolveAt(kr, value)
}

// resolveAt resolves a reference against a specific ring (used by tests).
func resolveAt(kr *Ring, value string) (string, error) {
	if !strings.HasPrefix(value, "keyring:") {
		return value, nil
	}
	name := strings.TrimPrefix(value, "keyring:")
	secret, ok, err := kr.Get(name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("keyring has no entry %q; store one with `kproxy keyring set %s`", name, name)
	}
	return secret, nil
}
