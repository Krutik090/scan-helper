// Package config loads scan-helper's YAML configuration.
//
// Every field has a default matching the Node implementation's old .env
// defaults, so a config file only needs to state what differs. Two
// invariants are enforced before the server is allowed to start: an API
// key must be set (a fresh deployment must never run unauthenticated),
// and mongo mode must have a URI to write to.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeMongo       Mode = "mongo"
	ModeAPIResponse Mode = "api_response"
)

type ServerConfig struct {
	Port   int    `yaml:"port"`
	APIKey string `yaml:"api_key"`
}

type MongoConfig struct {
	URI string `yaml:"uri"`
}

type SubdomainModuleConfig struct {
	Enabled         bool   `yaml:"enabled"`
	SubfinderBin    string `yaml:"subfinder_bin"`
	AmassBin        string `yaml:"amass_bin"`
	TimeoutMinutes  int    `yaml:"timeout_minutes"`
	ResolverWorkers int    `yaml:"resolver_workers"`
}

type PortscanModuleConfig struct {
	Enabled        bool   `yaml:"enabled"`
	NmapBin        string `yaml:"nmap_bin"`
	TimeoutMinutes int    `yaml:"timeout_minutes"`
	WorkerPool     int    `yaml:"worker_pool"`
}

type ModulesConfig struct {
	Subdomain SubdomainModuleConfig `yaml:"subdomain"`
	Portscan  PortscanModuleConfig  `yaml:"portscan"`
}

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Mode    Mode          `yaml:"mode"`
	Mongo   MongoConfig   `yaml:"mongo"`
	Modules ModulesConfig `yaml:"modules"`
}

// Defaults returns the built-in configuration defaults, with every module
// enabled. It exists so callers can inspect what the binary needs (tool
// paths, etc.) before any config file exists — see cmd/scan-helper's
// -print-tools flag, which must work on a fresh box with no config.yaml.
func Defaults() Config {
	return defaults()
}

func defaults() Config {
	return Config{
		Server: ServerConfig{Port: 4001},
		Mode:   ModeMongo,
		Mongo:  MongoConfig{URI: "mongodb://localhost:27017/ThreatIntel"},
		Modules: ModulesConfig{
			Subdomain: SubdomainModuleConfig{
				Enabled:         true,
				SubfinderBin:    "subfinder",
				AmassBin:        "amass",
				TimeoutMinutes:  5,
				ResolverWorkers: 50,
			},
			Portscan: PortscanModuleConfig{
				Enabled:        true,
				NmapBin:        "nmap",
				TimeoutMinutes: 10,
				WorkerPool:     5,
			},
		},
	}
}

// Load reads path, layering it over the defaults, then validates.
// Unmarshalling into an already-populated struct leaves any key the file
// doesn't mention at its default.
func Load(path string) (Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces what must be true before the server starts.
func (c Config) Validate() error {
	if c.Server.APIKey == "" {
		return fmt.Errorf("server.api_key is required — refusing to start with no API authentication")
	}
	if c.Mode != ModeMongo && c.Mode != ModeAPIResponse {
		return fmt.Errorf("mode must be %q or %q, got %q", ModeMongo, ModeAPIResponse, c.Mode)
	}
	if c.Mode == ModeMongo && c.Mongo.URI == "" {
		return fmt.Errorf("mongo.uri is required when mode is %q", ModeMongo)
	}
	if !c.Modules.Subdomain.Enabled && !c.Modules.Portscan.Enabled {
		return fmt.Errorf("at least one module must be enabled")
	}
	return nil
}
