package engine

import (
	"fmt"
	"net"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/policy"
	"github.com/mazdakn/fwsim/pkg/traffic"
)

type Config struct {
	Rules   []RuleConfig   `yaml:"rules,omitempty"`
	Packets []PacketConfig `yaml:"packets,omitempty"`
}

type RuleConfig struct {
	SrcNet   string  `yaml:"src_net,omitempty"`
	DstNet   string  `yaml:"dst_net,omitempty"`
	Protocol *uint8  `yaml:"protocol,omitempty"`
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

type PacketConfig struct {
	SrcAddr  string `yaml:"src_addr,omitempty"`
	DstAddr  string `yaml:"dst_addr,omitempty"`
	Protocol uint8  `yaml:"protocol,omitempty"`
	SrcPort  uint16 `yaml:"src_port,omitempty"`
	DstPort  uint16 `yaml:"dst_port,omitempty"`
}

func (c *Config) ToPackets() ([]traffic.Packet, error) {
	var packets []traffic.Packet
	for _, pc := range c.Packets {
		var opts []traffic.PacketOption
		if pc.SrcAddr != "" {
			opts = append(opts, traffic.WithSrcAddr(pc.SrcAddr))
		}
		if pc.DstAddr != "" {
			opts = append(opts, traffic.WithDstAddr(pc.DstAddr))
		}
		opts = append(opts, traffic.WithProto(pc.Protocol))
		opts = append(opts, traffic.WithSrcPort(pc.SrcPort))
		opts = append(opts, traffic.WithDstPort(pc.DstPort))

		packets = append(packets, *traffic.NewPacket(opts...))
	}
	return packets, nil
}
