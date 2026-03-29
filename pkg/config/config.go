package config

import (
	"fmt"

	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/model/packet"
)

type Config struct {
	Rules         []model.RuleConfig `yaml:"rules,omitempty"`
	DefaultAction string             `yaml:"default_action,omitempty"`
}

type PacketsConfig struct {
	Packets []packet.PacketConfig `yaml:"packets,omitempty"`
}

func (c *Config) Validate() error {
	if err := c.validateRules(); err != nil {
		return fmt.Errorf("failed to validate rules: %w", err)
	}
	if c.DefaultAction == "" {
		return fmt.Errorf("default_action is required")
	}
	if !c.validateAction(c.DefaultAction) {
		return fmt.Errorf("invalid default_action %s", c.DefaultAction)
	}
	return nil
}

func (c *Config) validateRules() error {
	for _, r := range c.Rules {
		if err := c.validateStructFields(r); err != nil {
			return err
		}
	}
	return nil
}

func (p *PacketsConfig) Validate() error {
	c := &Config{}
	for _, pkt := range p.Packets {
		if err := c.validateStructFields(pkt); err != nil {
			return fmt.Errorf("invalid packet config: %w", err)
		}
	}
	return nil
}
