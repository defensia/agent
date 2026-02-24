package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const defaultPath = "/etc/defensia/config.json"

type Config struct {
	ServerURL    string `json:"server_url"`
	AgentToken   string `json:"agent_token"`
	AgentID      int64  `json:"agent_id"`
	ReverbURL    string `json:"reverb_url"`
	ReverbAppKey string `json:"reverb_app_key"`
	AuthEndpoint string `json:"auth_endpoint"`
}

func path() string {
	if p := os.Getenv("DEFENSIA_CONFIG"); p != "" {
		return p
	}
	return defaultPath
}

func Load() (*Config, error) {
	data, err := os.ReadFile(path())
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.ServerURL == "" || cfg.AgentToken == "" {
		return nil, errors.New("config is incomplete: server_url and agent_token are required")
	}

	return &cfg, nil
}

func Save(cfg *Config) error {
	p := path()

	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(p, data, 0o600)
}
