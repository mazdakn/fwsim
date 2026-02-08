package engine

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/policy"
	"github.com/mazdakn/fwsim/pkg/traffic"
)

type Config struct {
	Rules        []RuleConfig  `yaml:"rules,omitempty"`
	Expectations []Expectation `yaml:"expectations,omitempty"`
}

type RuleConfig struct {
	SrcNet   string  `yaml:"src_net,omitempty"`
	DstNet   string  `yaml:"dst_net,omitempty"`
	Protocol *uint8  `yaml:"proto,omitempty"`
	SrcPort  *uint16 `yaml:"src_port,omitempty"`
	DstPort  *uint16 `yaml:"dst_port,omitempty"`
	Action   string  `yaml:"action,omitempty"`
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

		switch strings.ToLower(rc.Action) {
		case "accept":
			rule.Action = policy.Accept
		case "drop": // Drop or Deny?
			rule.Action = policy.Drop
		default:
			return nil, fmt.Errorf("unknown action: %s", rc.Action)
		}
		rules = append(rules, *rule)
	}
	return rules, nil
}

type Expectation struct {
	Result string       `yaml:"result,omitempty"`
	Packet PacketConfig `yaml:"packet,omitempty"`
}

// TODO: maybe use model.Packet directly
// TODO: all fields must be set. Consider using CEL to validate.
type PacketConfig struct {
	SrcAddr string `yaml:"src_addr,omitempty"`
	DstAddr string `yaml:"dst_addr,omitempty"`
	Proto   uint8  `yaml:"proto,omitempty"`
	SrcPort uint16 `yaml:"src_port,omitempty"`
	DstPort uint16 `yaml:"dst_port,omitempty"`
}

func (c *Config) ToPacket(pc PacketConfig) (*traffic.Packet, error) {
	var opts []traffic.PacketOption
	// TODO: must validate src and dst addr
	if pc.SrcAddr != "" {
		if ip := net.ParseIP(pc.SrcAddr); ip == nil {
			return nil, fmt.Errorf("invalid src addr %s", pc.SrcAddr)
		}
		opts = append(opts, traffic.WithSrcAddr(pc.SrcAddr))
	}
	if pc.DstAddr != "" {
		if ip := net.ParseIP(pc.DstAddr); ip == nil {
			return nil, fmt.Errorf("invalid dst addr %s", pc.DstAddr)
		}
		opts = append(opts, traffic.WithDstAddr(pc.DstAddr))
	}
	opts = append(opts, traffic.WithProto(pc.Proto))
	opts = append(opts, traffic.WithSrcPort(pc.SrcPort))
	opts = append(opts, traffic.WithDstPort(pc.DstPort))
	return traffic.NewPacket(opts...), nil
}
