// Package auth hashes API key secrets with argon2id and generates new
// high-entropy secrets. Secrets are random (128 bits), so the stored hashes
// cannot be reversed even if the key file leaks.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. Time/memory are tuned for a small VPS with a handful
// of keys: each verification costs ~64 MiB and a few tens of milliseconds.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

var b64 = base64.RawStdEncoding

// HashSecret returns an argon2id PHC string encoding the secret.
func HashSecret(secret string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifySecret reports whether secret matches the argon2id PHC string. It
// compares hashes in constant time.
func VerifySecret(secret, encoded string) bool {
	params, salt, key, err := decodePHC(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(secret), salt, params.time, params.memory, params.threads, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1
}

// NewSecret returns a random high-entropy secret with a kproxy_ prefix.
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "kproxy_" + hex.EncodeToString(b), nil
}

type phcParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodePHC(encoded string) (phcParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return phcParams{}, nil, nil, errors.New("invalid argon2id hash")
	}
	var p phcParams
	for _, kv := range strings.Split(parts[3], ",") {
		switch {
		case strings.HasPrefix(kv, "m="):
			v, err := strconv.Atoi(strings.TrimPrefix(kv, "m="))
			if err != nil {
				return p, nil, nil, errors.New("invalid argon2id memory")
			}
			p.memory = uint32(v)
		case strings.HasPrefix(kv, "t="):
			v, err := strconv.Atoi(strings.TrimPrefix(kv, "t="))
			if err != nil {
				return p, nil, nil, errors.New("invalid argon2id time")
			}
			p.time = uint32(v)
		case strings.HasPrefix(kv, "p="):
			v, err := strconv.Atoi(strings.TrimPrefix(kv, "p="))
			if err != nil {
				return p, nil, nil, errors.New("invalid argon2id threads")
			}
			p.threads = uint8(v)
		}
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, errors.New("invalid argon2id salt")
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, errors.New("invalid argon2id key")
	}
	return p, salt, key, nil
}
