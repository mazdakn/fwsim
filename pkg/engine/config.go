package engine

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
	validator, err := getValidator()
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
		for _, srcNet := range r.SrcNet {
			if !validator.validateCIDR(srcNet) {
				return fmt.Errorf("invalid src_net %s", srcNet)
			}
		}

		for _, dstNet := range r.DstNet {
			if !validator.validateCIDR(dstNet) {
				return fmt.Errorf("invalid dst_net %s", dstNet)
			}
		}

		for _, srcNet := range r.NegSrcNet {
			if !validator.validateCIDR(srcNet) {
				return fmt.Errorf("invalid neg_src_net %s", srcNet)
			}
		}

		for _, dstNet := range r.NegDstNet {
			if !validator.validateCIDR(dstNet) {
				return fmt.Errorf("invalid neg_dst_net %s", dstNet)
			}
		}

		if !validator.validateAction(r.Action) {
			return fmt.Errorf("invalid action %s", r.Action)
		}
	}

	return nil
}
