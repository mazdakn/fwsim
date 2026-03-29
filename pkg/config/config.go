package config

import (
	"github.com/mazdakn/fwsim/internal/rule"
	"github.com/mazdakn/fwsim/internal/packet"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Config struct {
	Rules         []rule.RuleConfig `yaml:"rules,omitempty"`
	DefaultAction string             `yaml:"default_action,omitempty" validate:"isValidAction"`
}

func (c *Config) Validate() error {
	return validator.ValidateStructFields(c)
}

type PacketsConfig struct {
	Packets []packet.PacketConfig `yaml:"packets,omitempty"`
}

func (p *PacketsConfig) Validate() error {
	return validator.ValidateStructFields(p)
}
