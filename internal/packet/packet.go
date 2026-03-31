package packet

import (
	"fmt"
	"net"
)

type PacketOption func(*Packet)

func WithName(name string) PacketOption {
	return func(p *Packet) {
		p.Metadata.Name = name
	}
}

func WithProto(proto uint8) PacketOption {
	return func(p *Packet) {
		p.Proto = proto
	}
}

func WithSrcPort(port uint16) PacketOption {
	return func(p *Packet) {
		p.SrcPort = port
	}
}

func WithDstPort(port uint16) PacketOption {
	return func(p *Packet) {
		p.DstPort = port
	}
}

func WithSrcAddr(addr string) PacketOption {
	return func(p *Packet) {
		p.SrcAddr = net.ParseIP(addr)
	}
}

func WithDstAddr(addr string) PacketOption {
	return func(p *Packet) {
		p.DstAddr = net.ParseIP(addr)
	}
}

func New(opts ...PacketOption) *Packet {
	p := Packet{
		Metadata: NewMetadata(),
	}
	for _, o := range opts {
		o(&p)
	}
	return &p
}

type Packet struct {
	SrcAddr net.IP
	DstAddr net.IP

	Proto uint8

	SrcPort uint16
	DstPort uint16

	Metadata *Metadata
}

// PacketConfig is the YAML configuration structure for a single packet.
type PacketConfig struct {
	Name    string   `yaml:"name,omitempty"`
	SrcAddr string   `yaml:"src_addr,omitempty" validate:"isValidIP"`
	DstAddr string   `yaml:"dst_addr,omitempty" validate:"isValidIP"`
	Proto   uint8    `yaml:"proto,omitempty"    validate:"isProtoValid"`
	SrcPort uint16   `yaml:"src_port,omitempty" validate:"isPortValid"`
	DstPort uint16   `yaml:"dst_port,omitempty" validate:"isPortValid"`
}

// ToPacket converts a PacketConfig into a Packet domain object.
func (p *PacketConfig) ToPacket() *Packet {
	return New(
		WithName(p.Name),
		WithSrcAddr(p.SrcAddr),
		WithDstAddr(p.DstAddr),
		WithProto(p.Proto),
		WithSrcPort(p.SrcPort),
		WithDstPort(p.DstPort),
	)
}

func (p *Packet) String() string {
	if p.Metadata.Name != "" {
		return p.Metadata.Name
	}
	return fmt.Sprintf("%d{%s:%d->%s:%d}", p.Proto, p.SrcAddr.String(), p.SrcPort,
		p.DstAddr.String(), p.DstPort)
}
