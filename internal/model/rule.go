package model

import (
	"fmt"
	"net"
	"strings"

	"github.com/mazdakn/fwsim/internal/counter"
	"github.com/mazdakn/fwsim/internal/set"
	"github.com/mazdakn/fwsim/internal/traffic"
)

type Action int

const (
	Accept Action = iota
	Drop
)

func (a Action) String() string {
	switch a {
	case Accept:
		return "Accept"
	case Drop:
		return "Drop"
	default:
		return fmt.Sprintf("Undefined(%d)", a)
	}
}

func (a Action) Validate() error {
	switch a {
	case Accept, Drop:
		return nil
	default:
		return fmt.Errorf("undefined action %v", a)
	}
}

// ParseAction parses an action string into an Action type
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "accept":
		return Accept, nil
	case "drop":
		return Drop, nil
	default:
		return Action(0), fmt.Errorf("unknown action: %s", s)
	}
}

type RuleOption func(*Rule)

func WithProto(proto uint8) RuleOption {
	return func(r *Rule) {
		if r.Proto == nil {
			r.Proto = set.NewProtoSet()
		}
		r.Proto.Add(proto)
	}
}

func WithSrcPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.SrcPort == nil {
			r.SrcPort = set.NewPortSet()
		}
		r.SrcPort.Add(port)
	}
}

func WithDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.DstPort == nil {
			r.DstPort = set.NewPortSet()
		}
		r.DstPort.Add(port)
	}
}

func WithSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.SrcNet == nil {
			r.SrcNet = set.NewIPSet()
		}
		r.SrcNet.Add(MustParseCIDR(cidr))
	}
}

func WithDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.DstNet == nil {
			r.DstNet = set.NewIPSet()
		}
		r.DstNet.Add(MustParseCIDR(cidr))
	}
}

func WithAction(action Action) RuleOption {
	return func(r *Rule) {
		r.Action = action
	}
}

func WithName(name string) RuleOption {
	return func(r *Rule) {
		r.Name = name
	}
}

func WithOrder(order uint64) RuleOption {
	return func(r *Rule) {
		r.Order = order
	}
}

func NewRule(opts ...RuleOption) *Rule {
	r := Rule{
		packetCount: counter.New(),
	}
	for _, o := range opts {
		o(&r)
	}
	return &r
}

type Rule struct {
	Name   string
	Order  uint64
	SrcNet *set.IPSet
	DstNet *set.IPSet
	Proto  *set.ProtoSet

	SrcPort *set.PortSet
	DstPort *set.PortSet

	Action Action

	packetCount *counter.Counter
}

func (r *Rule) Match(pkt *traffic.Packet) bool {
	if r.Proto != nil && !r.Proto.Match(pkt.Protocol) {
		return false
	}
	if r.SrcPort != nil && !r.SrcPort.Match(pkt.SrcPort) {
		return false
	}
	if r.DstPort != nil && !r.DstPort.Match(pkt.DstPort) {
		return false
	}
	if r.SrcNet != nil && !r.SrcNet.Match(pkt.SrcAddr) {
		return false
	}
	if r.DstNet != nil && !r.DstNet.Match(pkt.DstAddr) {
		return false
	}
	// All conditions passed - increment packet counter
	r.packetCount.Increment()
	return true
}

func (r *Rule) PacketCount() uint64 {
	return r.packetCount.Get()
}

func (r *Rule) ResetPacketCount() {
	r.packetCount.Reset()
}

func (r *Rule) String() string {
	if r.Name != "" {
		return r.Name
	}
	proto := "*"
	if r.Proto != nil {
		proto = r.Proto.String()
	}
	srcPort := "*"
	if r.SrcPort != nil {
		srcPort = r.SrcPort.String()
	}
	dstPort := "*"
	if r.DstPort != nil {
		dstPort = r.DstPort.String()
	}
	srcNet := "*"
	if r.SrcNet != nil {
		srcNet = r.SrcNet.String()
	}
	dstNet := "*"
	if r.DstNet != nil {
		dstNet = r.DstNet.String()
	}
	return fmt.Sprintf("%s %s{%s:%s->%s:%s}", r.Action, proto, srcNet, srcPort, dstNet, dstPort)
}

func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("CIDR %s is invalid", cidr))
	}
	return ipnet
}
