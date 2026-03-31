package config

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/rule"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Config struct {
	Rules         []rule.RuleConfig `yaml:"rules,omitempty"`
	DefaultAction string            `yaml:"default_action,omitempty" validate:"isValidAction"`
}

func (c *Config) Validate() error {
	return validator.ValidateStructFields(c)
}

func ConfigFromFile(file string) (*Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
