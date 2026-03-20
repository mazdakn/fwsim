package model

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mazdakn/fwsim/internal/counter"
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
		r.Protocol = &proto
	}
}

func WithSrcPort(port uint16) RuleOption {
	return func(r *Rule) {
		r.SrcPort = &port
	}
}

func WithDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		r.DstPort = &port
	}
}

func WithSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		r.SrcNet = MustParseCIDR(cidr)
	}
}

func WithDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		r.DstNet = MustParseCIDR(cidr)
	}
}

func WithAction(action Action) RuleOption {
	return func(r *Rule) {
		r.Action = action
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
	SrcNet   *net.IPNet
	DstNet   *net.IPNet
	Protocol *uint8

	SrcPort *uint16
	DstPort *uint16

	Action Action

	packetCount *counter.Counter
}

func (r *Rule) Match(pkt *traffic.Packet) bool {
	if r.Protocol != nil && *r.Protocol != pkt.Protocol {
		return false
	}
	if r.SrcPort != nil && *r.SrcPort != pkt.SrcPort {
		return false
	}
	if r.DstPort != nil && *r.DstPort != pkt.DstPort {
		return false
	}
	if r.SrcNet != nil && !r.SrcNet.Contains(pkt.SrcAddr) {
		return false
	}
	if r.DstNet != nil && !r.DstNet.Contains(pkt.DstAddr) {
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
	proto := "*"
	if r.Protocol != nil {
		proto = strconv.Itoa(int(*r.Protocol))
	}
	srcPort := "*"
	if r.SrcPort != nil {
		srcPort = strconv.Itoa(int(*r.SrcPort))
	}
	dstPort := "*"
	if r.DstPort != nil {
		dstPort = strconv.Itoa(int(*r.DstPort))
	}
	srcNet := "*"
	if r.SrcNet != nil {
		srcNet = r.SrcNet.String()
	}
	dstNet := "*"
	if r.DstNet != nil {
		dstNet = r.DstNet.String()
	}
	return fmt.Sprintf("%s{%s:%s->%s:%s}", proto, srcNet, srcPort, dstNet, dstPort)
}

func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("CIDR %s is invalid", cidr))
	}
	return ipnet
}
