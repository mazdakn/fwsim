package config

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Packet struct {
	SrcAddr string      `yaml:"src_addr,omitempty" validate:"isValidIP"`
	DstAddr string      `yaml:"dst_addr,omitempty" validate:"isValidIP"`
	Proto   proto.Proto `yaml:"proto,omitempty"    validate:"isProtoValid"`
	SrcPort port.Port   `yaml:"src_port,omitempty" validate:"isPortValid"`
	DstPort port.Port   `yaml:"dst_port,omitempty" validate:"isPortValid"`

	Metadata packet.Metadata `yaml:"metadata,omitempty"`
}

func (p *Packet) Validate() error {
	return validator.ValidateStructFields(p)
}

func (p *Packet) ToPacket() *packet.Packet {
	return packet.New(
		packet.WithName(p.Metadata.Name),
		packet.WithSrcAddr(p.SrcAddr),
		packet.WithDstAddr(p.DstAddr),
		packet.WithProto(p.Proto),
		packet.WithSrcPort(p.SrcPort.Resolve()),
		packet.WithDstPort(p.DstPort.Resolve()),
		packet.WithIngressIface(p.Metadata.IngressIface),
		packet.WithEgressIface(p.Metadata.EgressIface),
	)
}

func PacketsFromBytes(data []byte) ([]*packet.Packet, error) {
	var p Packet
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return []*packet.Packet{p.ToPacket()}, nil
}

func PacketsFromFile(file string) ([]*packet.Packet, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return PacketsFromBytes(data)
}
