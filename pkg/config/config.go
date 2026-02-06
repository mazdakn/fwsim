package config

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Config represents the top-level configuration structure
type Config struct {
	Policies []PolicyRule `yaml:"Policies"`
	Traffic  []TrafficRule `yaml:"traffic"`
}

// PolicyRule represents a firewall policy rule
type PolicyRule struct {
	Match  []Match `yaml:"match"`
	Action string  `yaml:"action"`
}

// Match represents matching criteria for a policy rule
type Match struct {
	Src   string `yaml:"src,omitempty"`
	Dst   string `yaml:"dst,omitempty"`
	Proto string `yaml:"proto,omitempty"`
}

// TrafficRule represents a traffic test case
type TrafficRule struct {
	Src    string `yaml:"src"`
	Dst    string `yaml:"dst"`
	Proto  string `yaml:"proto"`
	Result string `yaml:"result"`
}

// LoadConfig loads and parses a YAML configuration file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return ParseConfig(data)
}

// ParseConfig parses YAML configuration from a byte slice
func ParseConfig(data []byte) (*Config, error) {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &config, nil
}
