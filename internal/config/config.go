// Package config manages kproxy client configuration files. Secrets (the API
// key) are stored with restrictive file permissions; callers may instead use
// the OS-backed keyring (internal/keyring) via keyring:NAME references.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// AgentConfig is persisted per user on the machine running the agent.
type AgentConfig struct {
	ServerURL string `json:"server_url"`
	APIKey    string `json:"api_key"`
}

// TunnelEntry is one tunnel inside a TunnelFile.
type TunnelEntry struct {
	Proto     string `json:"proto"`
	Local     string `json:"local"`
	Port      int    `json:"port,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	Domain    string `json:"domain,omitempty"`
	// Security options, all optional.
	BasicAuth      string   `json:"basic_auth,omitempty"`
	IPAllow        []string `json:"ip_allow,omitempty"`
	IPDeny         []string `json:"ip_deny,omitempty"`
	MaxRequestSize string   `json:"max_request_size,omitempty"`
	RequestTimeout string   `json:"request_timeout,omitempty"`
}

// TunnelFile defines multiple tunnels to open from a single agent process.
// The server and api_key fields are optional; CLI flags, environment
// variables and the credential config file take precedence.
type TunnelFile struct {
	ServerURL string        `json:"server_url,omitempty"`
	APIKey    string        `json:"api_key,omitempty"`
	Tunnels   []TunnelEntry `json:"tunnels"`
}

// LoadTunnelFile reads a tunnel definition file.
func LoadTunnelFile(path string) (TunnelFile, error) {
	var tf TunnelFile
	b, err := os.ReadFile(path)
	if err != nil {
		return tf, err
	}
	if err := json.Unmarshal(b, &tf); err != nil {
		return tf, err
	}
	if len(tf.Tunnels) == 0 {
		return tf, errors.New("tunnel file must define at least one tunnel")
	}
	return tf, nil
}

// AgentPath returns the platform-appropriate config file path.
func AgentPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "kproxy", "config.json"), nil
}

// LoadAgent reads the agent config from the default location. It returns an
// empty config (and no error) when the file does not exist.
func LoadAgent() (AgentConfig, error) {
	return LoadAgentAt("")
}

// LoadAgentAt reads the agent config from path, or the default location when
// path is empty. It returns an empty config (and no error) when the file does
// not exist.
func LoadAgentAt(path string) (AgentConfig, error) {
	var c AgentConfig
	if path == "" {
		var err error
		path, err = AgentPath()
		if err != nil {
			return c, err
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, nil
}

// SaveAgent writes the agent config to the default location, creating
// directories as needed.
func SaveAgent(c AgentConfig) error {
	return SaveAgentAt(c, "")
}

// SaveAgentAt writes the agent config to path, or the default location when
// path is empty, creating directories as needed.
func SaveAgentAt(c AgentConfig, path string) error {
	if path == "" {
		var err error
		path, err = AgentPath()
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
