package engine

import (
	"fmt"
	"net"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/policy"
)

type Config struct {
	Rules []RuleConfig `yaml:"rules"`
}

type RuleConfig struct {
	SrcNet   string  `yaml:"src_net"`
	DstNet   string  `yaml:"dst_net"`
	Protocol *uint8  `yaml:"protocol"`
	SrcPort  *uint16 `yaml:"src_port"`
	DstPort  *uint16 `yaml:"dst_port"`
	Action   string  `yaml:"action"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) ToPolicyRules() ([]policy.Rule, error) {
	var rules []policy.Rule
	for _, rc := range c.Rules {
		var opts []policy.RuleOption
		if rc.SrcNet != "" {
			if _, _, err := net.ParseCIDR(rc.SrcNet); err != nil {
				return nil, fmt.Errorf("invalid src_net %s: %w", rc.SrcNet, err)
			}
			opts = append(opts, policy.WithSrcNet(rc.SrcNet))
		}
		if rc.DstNet != "" {
			if _, _, err := net.ParseCIDR(rc.DstNet); err != nil {
				return nil, fmt.Errorf("invalid dst_net %s: %w", rc.DstNet, err)
			}
			opts = append(opts, policy.WithDstNet(rc.DstNet))
		}
		if rc.Protocol != nil {
			opts = append(opts, policy.WithProto(*rc.Protocol))
		}
		if rc.SrcPort != nil {
			opts = append(opts, policy.WithSrcPort(*rc.SrcPort))
		}
		if rc.DstPort != nil {
			opts = append(opts, policy.WithDstPort(*rc.DstPort))
		}

		rule := policy.NewRule(opts...)

		switch rc.Action {
		case "Allow", "Accept":
			rule.Action = policy.Accept
		case "Drop":
			rule.Action = policy.Drop
		case "Reject":
			rule.Action = policy.Reject
		case "Log":
			rule.Action = policy.Log
		default:
			return nil, fmt.Errorf("unknown action: %s", rc.Action)
		}
		rules = append(rules, *rule)
	}
	return rules, nil
}
