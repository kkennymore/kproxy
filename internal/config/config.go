// Package config manages kproxy client configuration files. Secrets (the API
// key) are stored with restrictive file permissions; callers may prefer the
// OS keyring instead, which is a planned extension.
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
