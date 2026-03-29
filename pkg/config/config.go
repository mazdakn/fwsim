package config

import (
	"fmt"

	"github.com/mazdakn/fwsim/internal"
	"github.com/mazdakn/fwsim/internal/packet"
)

type Config struct {
	Rules         []model.RuleConfig `yaml:"rules,omitempty"`
	DefaultAction string             `yaml:"default_action,omitempty"`
}

type PacketsConfig struct {
	Packets []packet.PacketConfig `yaml:"packets,omitempty"`
}

func (c *Config) Validate() error {
	validator, err := newConfigValidator()
	if err != nil {
		return err
	}
	if err := c.validateRules(validator); err != nil {
		return fmt.Errorf("failed to validate rules: %w", err)
	}
	if c.DefaultAction == "" {
		return fmt.Errorf("default_action is required")
	}
	if !validator.validateAction(c.DefaultAction) {
		return fmt.Errorf("invalid default_action %s", c.DefaultAction)
	}
	return nil
}

func (c *Config) validateRules(validator *configValidator) error {
	for _, r := range c.Rules {
		if err := validator.validateStructFields(r); err != nil {
			return err
		}
	}
	return nil
}

func (c *PacketsConfig) Validate() error {
	validator, err := newConfigValidator()
	if err != nil {
		return err
	}
	for _, p := range c.Packets {
		if err := validator.validateStructFields(p); err != nil {
			return fmt.Errorf("invalid packet config: %w", err)
		}
	}
	return nil
}
