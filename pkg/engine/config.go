package engine

import (
	"fmt"
	"net"

	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/traffic"
)

type Config struct {
	Rules        []model.Rule  `yaml:"rules,omitempty"`
	Expectations []Expectation `yaml:"expectations,omitempty"`
}

func (c *Config) ToPolicyRules() ([]model.Rule, error) {
	// Rules are already in the correct format and validated during YAML unmarshaling
	// in Rule.UnmarshalYAML, so we just return them directly
	return c.Rules, nil
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
