// Package store implements the relay's API-key store as an atomic JSON file
// on disk. It stays stdlib-only to preserve kproxy's single-dependency
// promise; a single VPS deployment is far below the point where a database is
// warranted.
//
// Secrets are never persisted. The store keeps an argon2id hash (from
// internal/auth) plus a sha256 fingerprint used as an O(1) lookup index. The
// fingerprint is safe to store because secrets are 128-bit random values.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"kproxy/internal/auth"
)

// KeyInfo is the public view of an API key, safe to return to operators. The
// hash and fingerprint never leave the store.
type KeyInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
	Limits    Limits    `json:"limits,omitempty"`
}

// Limits caps what a key may do. A zero value means "unlimited" / "any".
type Limits struct {
	// RequestsPerSec caps HTTP tunnel requests; 0 means unlimited.
	RequestsPerSec int `json:"requests_per_sec,omitempty"`
	// BandwidthPerSec caps aggregate tunnel throughput in bytes per second;
	// 0 means unlimited.
	BandwidthPerSec int64 `json:"bandwidth_per_sec,omitempty"`
	// AllowedSubdomains restricts which subdomains or custom domains a key
	// may claim; empty means any.
	AllowedSubdomains []string `json:"allowed_subdomains,omitempty"`
}

// IsZero reports whether no limits are configured.
func (l Limits) IsZero() bool {
	return l.RequestsPerSec == 0 && l.BandwidthPerSec == 0 && len(l.AllowedSubdomains) == 0
}

// KeyIdentity is what relay sees after a successful handshake: the key's ID
// and policy limits, used for per-key enforcement. Like KeyInfo it never
// carries the secret, hash or fingerprint.
type KeyIdentity struct {
	ID     string
	Limits Limits
}

// key is the on-disk record for one API key.
type key struct {
	KeyInfo
	Hash        string `json:"hash"`
	Fingerprint string `json:"fingerprint"`
}

// Store is a thread-safe, file-backed key store.
type Store struct {
	mu   sync.RWMutex
	path string
	keys map[string]*key // indexed by fingerprint
}

// Open loads the store at path, creating an empty one (and its directory) if
// it does not exist.
func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: path, keys: make(map[string]*key)}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	var list []*key
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("parse key store %s: %w", path, err)
	}
	for _, k := range list {
		s.keys[k.Fingerprint] = k
	}
	return s, nil
}

// Create generates a new API key with the given policy limits. ttl <= 0 means
// the key never expires. It returns the public info and the plaintext secret,
// which is only ever returned once.
func (s *Store) Create(name string, ttl time.Duration, limits Limits) (KeyInfo, string, error) {
	secret, err := auth.NewSecret()
	if err != nil {
		return KeyInfo{}, "", err
	}
	hash, err := auth.HashSecret(secret)
	if err != nil {
		return KeyInfo{}, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	info := KeyInfo{
		ID:        newKeyID(),
		Name:      name,
		CreatedAt: time.Now().UTC(),
		Revoked:   false,
		Limits:    limits,
	}
	if ttl > 0 {
		info.ExpiresAt = info.CreatedAt.Add(ttl)
	}
	s.keys[fpOf(secret)] = &key{
		KeyInfo:     info,
		Hash:        hash,
		Fingerprint: fpOf(secret),
	}
	if err := s.saveLocked(); err != nil {
		delete(s.keys, fpOf(secret))
		return KeyInfo{}, "", err
	}
	return info, secret, nil
}

// Revoke marks a key revoked by its public ID. Unknown IDs return an error.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.ID == id {
			if k.Revoked {
				return fmt.Errorf("key %s is already revoked", id)
			}
			k.Revoked = true
			return s.saveLocked()
		}
	}
	return fmt.Errorf("key %s not found", id)
}

// List returns all keys, newest first.
func (s *Store) List() []KeyInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]KeyInfo, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k.KeyInfo)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ValidateKey authenticates an agent api key. It returns a descriptive error
// for unknown, revoked or expired keys, and the key's identity (ID + policy
// limits) on success. It implements relay.KeyValidator.
func (s *Store) ValidateKey(secret string) (*KeyIdentity, error) {
	s.mu.RLock()
	k := s.keys[fpOf(secret)]
	s.mu.RUnlock()
	if k == nil {
		return nil, errors.New("invalid api key")
	}
	if k.Revoked {
		return nil, errors.New("api key revoked")
	}
	if !k.ExpiresAt.IsZero() && time.Now().After(k.ExpiresAt) {
		return nil, errors.New("api key expired")
	}
	if !auth.VerifySecret(secret, k.Hash) {
		return nil, errors.New("invalid api key")
	}
	return &KeyIdentity{ID: k.ID, Limits: k.Limits}, nil
}

// saveLocked atomically writes the store to disk. The caller must hold s.mu.
func (s *Store) saveLocked() error {
	list := make([]*key, 0, len(s.keys))
	for _, k := range s.keys {
		list = append(list, k)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func fpOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func newKeyID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "k_" + strings.ToLower(hex.EncodeToString(b))
}
