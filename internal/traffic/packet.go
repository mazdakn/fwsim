package traffic

import (
	"fmt"
	"net"
)

type PacketOption func(*Packet)

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
	SrcAddr  net.IP
	DstAddr  net.IP
	Protocol uint8

	SrcPort uint16
	DstPort uint16
}

func (p *Packet) String() string {
	return fmt.Sprintf("%d{%s:%d->%s:%d}", p.Protocol, p.SrcAddr.String(), p.SrcPort,
		p.DstAddr.String(), p.DstPort)
}

// packetYAML is a helper struct for YAML marshaling/unmarshaling
type packetYAML struct {
	SrcAddr string `yaml:"src_addr,omitempty"`
	DstAddr string `yaml:"dst_addr,omitempty"`
	Proto   uint8  `yaml:"proto,omitempty"`
	SrcPort uint16 `yaml:"src_port,omitempty"`
	DstPort uint16 `yaml:"dst_port,omitempty"`
}

func (p *Packet) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var py packetYAML
	if err := unmarshal(&py); err != nil {
		return err
	}

	// Parse SrcAddr
	if py.SrcAddr != "" {
		ip := net.ParseIP(py.SrcAddr)
		if ip == nil {
			return fmt.Errorf("invalid src_addr %s", py.SrcAddr)
		}
		p.SrcAddr = ip
	}

	// Parse DstAddr
	if py.DstAddr != "" {
		ip := net.ParseIP(py.DstAddr)
		if ip == nil {
			return fmt.Errorf("invalid dst_addr %s", py.DstAddr)
		}
		p.DstAddr = ip
	}

	// Copy other fields
	p.Protocol = py.Proto
	p.SrcPort = py.SrcPort
	p.DstPort = py.DstPort

	return nil
}

func (p Packet) MarshalYAML() (interface{}, error) {
	py := packetYAML{
		Proto:   p.Protocol,
		SrcPort: p.SrcPort,
		DstPort: p.DstPort,
	}

	if p.SrcAddr != nil {
		py.SrcAddr = p.SrcAddr.String()
	}
	if p.DstAddr != nil {
		py.DstAddr = p.DstAddr.String()
	}

	return py, nil
}
