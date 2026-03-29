package config

import (
	"fmt"

	model "github.com/mazdakn/fwsim/internal"
	"github.com/mazdakn/fwsim/internal/packet"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Config struct {
	Rules         []model.RuleConfig `yaml:"rules,omitempty"`
	DefaultAction string             `yaml:"default_action,omitempty" validate:"isValidAction"`
}

func (c *Config) Validate() error {
	for _, r := range c.Rules {
		if err := validator.ValidateStructFields(r); err != nil {
			return err
		}
	}
	if err := validator.ValidateStructFields(c); err != nil {
		return err
	}
	return nil
}

type PacketsConfig struct {
	Packets []packet.PacketConfig `yaml:"packets,omitempty"`
}

func (p *PacketsConfig) Validate() error {
	for _, pkt := range p.Packets {
		if err := validator.ValidateStructFields(pkt); err != nil {
			return fmt.Errorf("invalid packet config: %w", err)
		}
	}
	return nil
}
