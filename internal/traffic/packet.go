package traffic

import (
	"fmt"
	"net"
)

type PacketOption func(*Packet)

func WithName(name string) PacketOption {
	return func(p *Packet) {
		p.Name = name
	}
}

func WithProto(proto uint8) PacketOption {
	return func(p *Packet) {
		p.Protocol = proto
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

func NewPacket(opts ...PacketOption) *Packet {
	var p Packet
	for _, o := range opts {
		o(&p)
	}
	return &p
}

type Packet struct {
	Name     string
	SrcAddr  net.IP
	DstAddr  net.IP
	Protocol uint8

	SrcPort uint16
	DstPort uint16
}

func (p *Packet) String() string {
	if p.Name != "" {
		return p.Name
	}
	return fmt.Sprintf("%d{%s:%d->%s:%d}", p.Protocol, p.SrcAddr.String(), p.SrcPort,
		p.DstAddr.String(), p.DstPort)
}

type PacketConfig struct {
	Name    string `yaml:"name,omitempty"`
	SrcAddr string `yaml:"src_addr,omitempty"`
	DstAddr string `yaml:"dst_addr,omitempty"`
	Proto   uint8  `yaml:"proto,omitempty"`
	SrcPort uint16 `yaml:"src_port,omitempty"`
	DstPort uint16 `yaml:"dst_port,omitempty"`
}

func (pc *PacketConfig) ToPacket() *Packet {
	return NewPacket(
		WithName(pc.Name),
		WithSrcAddr(pc.SrcAddr),
		WithDstAddr(pc.DstAddr),
		WithProto(pc.Proto),
		WithSrcPort(pc.SrcPort),
		WithDstPort(pc.DstPort),
	)
}
