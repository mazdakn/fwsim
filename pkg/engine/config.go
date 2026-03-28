package engine

import (
	"fmt"
	"net"

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
	if _, err := model.ParseAction(c.DefaultAction); err != nil {
		return fmt.Errorf("invalid default_action %s: %w", c.DefaultAction, err)
	}
	return nil
}

func (c *Config) validateRules() error {
	for _, r := range c.Rules {
		for _, srcNet := range r.SrcNet {
			_, _, err := net.ParseCIDR(srcNet)
			if err != nil {
				return fmt.Errorf("invalid src_net %s: %w", srcNet, err)
			}
		}

		for _, dstNet := range r.DstNet {
			_, _, err := net.ParseCIDR(dstNet)
			if err != nil {
				return fmt.Errorf("invalid dst_net %s: %w", dstNet, err)
			}
		}

		for _, srcNet := range r.NegSrcNet {
			_, _, err := net.ParseCIDR(srcNet)
			if err != nil {
				return fmt.Errorf("invalid neg_src_net %s: %w", srcNet, err)
			}
		}

		for _, dstNet := range r.NegDstNet {
			_, _, err := net.ParseCIDR(dstNet)
			if err != nil {
				return fmt.Errorf("invalid neg_dst_net %s: %w", dstNet, err)
			}
		}

		if _, err := model.ParseAction(r.Action); err != nil {
			return fmt.Errorf("invalid action %s: %w", r.Action, err)
		}
	}

	return nil
}
