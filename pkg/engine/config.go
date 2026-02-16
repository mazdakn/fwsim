package engine

import (
	"fmt"
	"net"

	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/traffic"
)

type Config struct {
	Rules        []Rule        `yaml:"rules,omitempty"`
	Expectations []Expectation `yaml:"expectations,omitempty"`
}

type Expectation struct {
	Result string          `yaml:"result,omitempty"`
	Packet *traffic.Packet `yaml:"packet,omitempty"`
}

type Rule struct {
	SrcNet   string  `yaml:"src_net,omitempty"`
	DstNet   string  `yaml:"dst_net,omitempty"`
	Protocol *uint8  `yaml:"proto,omitempty"`
	SrcPort  *uint16 `yaml:"src_port,omitempty"`
	DstPort  *uint16 `yaml:"dst_port,omitempty"`
	Action   string  `yaml:"action,omitempty"`
}

func (c *Config) Validate() error {
	for _, r := range c.Rules {
		if r.SrcNet != "" {
			_, _, err := net.ParseCIDR(r.SrcNet)
			if err != nil {
				return fmt.Errorf("invalid src_net %s: %w", r.SrcNet, err)
			}
		}

		// Parse DstNet
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
