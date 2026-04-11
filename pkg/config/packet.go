package config

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type PacketConfig struct {
	Packets []Packet `yaml:"packets,omitempty"`
}

func (pc *PacketConfig) Validate() error {
	return validator.ValidateStructFields(pc)
}

type Packet struct {
	SrcAddr string      `yaml:"src_addr,omitempty" validate:"isValidIP"`
	DstAddr string      `yaml:"dst_addr,omitempty" validate:"isValidIP"`
	Proto   proto.Proto `yaml:"proto,omitempty"    validate:"isProtoValid"`
	SrcPort uint16      `yaml:"src_port,omitempty" validate:"isPortValid"`
	DstPort uint16      `yaml:"dst_port,omitempty" validate:"isPortValid"`

	Metadata packet.Metadata `yaml:"metadata,omitempty"`
}

func (p *Packet) ToPacket() *packet.Packet {
	return packet.New(
		packet.WithName(p.Metadata.Name),
		packet.WithSrcAddr(p.SrcAddr),
		packet.WithDstAddr(p.DstAddr),
		packet.WithProto(p.Proto),
		packet.WithSrcPort(p.SrcPort),
		packet.WithDstPort(p.DstPort),
	)
}

func PacketsFromFile(file string) ([]*packet.Packet, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var pc PacketConfig
	if err := yaml.Unmarshal(data, &pc); err != nil {
		return nil, err
	}
	if err := pc.Validate(); err != nil {
		return nil, err
	}
	pkts := make([]*packet.Packet, 0, len(pc.Packets))
	for _, p := range pc.Packets {
		pkts = append(pkts, p.ToPacket())
	}
	return pkts, nil
}
