package engine

import (
	"fmt"
	"net"

	"github.com/mazdakn/fwsim/internal/model"
)

type Config struct {
	Rules         []Rule `yaml:"rules,omitempty"`
	DefaultAction string `yaml:"default_action,omitempty"`
}

type Rule struct {
	SrcNet   string  `yaml:"src_net,omitempty"`
	DstNet   string  `yaml:"dst_net,omitempty"`
	Protocol *uint8  `yaml:"proto,omitempty"`
	SrcPort  *uint16 `yaml:"src_port,omitempty"`
	DstPort  *uint16 `yaml:"dst_port,omitempty"`
	Action   string  `yaml:"action,omitempty"`
}

type Packet struct {
	SrcAddr string `yaml:"src_addr,omitempty"`
	DstAddr string `yaml:"dst_addr,omitempty"`
	Proto   uint8  `yaml:"proto,omitempty"`
	SrcPort uint16 `yaml:"src_port,omitempty"`
	DstPort uint16 `yaml:"dst_port,omitempty"`
}

func (c *Config) Validate() error {
	if err := c.validateRules(); err != nil {
		return fmt.Errorf("failed to validate rules: %w", err)
	}
	if c.DefaultAction != "" {
		if _, err := model.ParseAction(c.DefaultAction); err != nil {
			return fmt.Errorf("invalid default_action %s: %w", c.DefaultAction, err)
		}
	}
	return nil
}

func (c *Config) validateRules() error {
	for _, r := range c.Rules {
		if r.SrcNet != "" {
			_, _, err := net.ParseCIDR(r.SrcNet)
			if err != nil {
				return fmt.Errorf("invalid src_net %s: %w", r.SrcNet, err)
			}
		}

		if r.DstNet != "" {
			_, _, err := net.ParseCIDR(r.DstNet)
			if err != nil {
				return fmt.Errorf("invalid dst_net %s: %w", r.DstNet, err)
			}
		}

		if _, err := model.ParseAction(r.Action); err != nil {
			return fmt.Errorf("invalid action %s: %w", r.Action, err)
		}
	}

	return nil
}
