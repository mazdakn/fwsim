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

func (p *Packet) String() string {
	if p.Metadata.Name != "" {
		return p.Metadata.Name
	}
	return fmt.Sprintf("%d{%s:%d->%s:%d}", p.Proto, p.SrcAddr.String(), p.SrcPort,
		p.DstAddr.String(), p.DstPort)
}

type PacketConfig struct {
	SrcAddr string `yaml:"src_addr,omitempty"`
	DstAddr string `yaml:"dst_addr,omitempty"`
	Proto   uint8  `yaml:"proto,omitempty"`
	SrcPort uint16 `yaml:"src_port,omitempty"`
	DstPort uint16 `yaml:"dst_port,omitempty"`

	Metadata Metadata `yaml:"metadata,omitempty"`
}

func (pc *PacketConfig) ToPacket() *Packet {
	return New(
		WithName(pc.Metadata.Name),
		WithSrcAddr(pc.SrcAddr),
		WithDstAddr(pc.DstAddr),
		WithProto(pc.Proto),
		WithSrcPort(pc.SrcPort),
		WithDstPort(pc.DstPort),
	)
}
