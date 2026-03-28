package model

import (
	"fmt"
	"net"
	"strings"

	"github.com/mazdakn/fwsim/internal/counter"
	"github.com/mazdakn/fwsim/internal/model/packet"
	"github.com/mazdakn/fwsim/internal/set"
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

func (r *Rule) Match(pkt *packet.Packet) bool {
	if r.Proto != nil && !r.Proto.Match(pkt.Proto) {
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

// RuleConfig represents the YAML configuration structure for a firewall rule.
type RuleConfig struct {
	Name     string   `yaml:"name,omitempty"`
	Order    uint64   `yaml:"order,omitempty"`
	SrcNet   []string `yaml:"src_net,omitempty"`
	DstNet   []string `yaml:"dst_net,omitempty"`
	Protocol []uint8  `yaml:"proto,omitempty"`
	SrcPort  []uint16 `yaml:"src_port,omitempty"`
	DstPort  []uint16 `yaml:"dst_port,omitempty"`
	Action   string   `yaml:"action,omitempty"`
}

// ToRule converts a RuleConfig into a Rule domain object.
func (rc *RuleConfig) ToRule() (*Rule, error) {
	rule := NewRule()
	rule.Name = rc.Name
	rule.Order = rc.Order

	if len(rc.Protocol) > 0 {
		rule.Proto = set.NewProtoSet()
		for _, proto := range rc.Protocol {
			rule.Proto.Add(proto)
		}
	}

	if len(rc.SrcPort) > 0 {
		rule.SrcPort = set.NewPortSet()
		for _, port := range rc.SrcPort {
			rule.SrcPort.Add(port)
		}
	}

	if len(rc.DstPort) > 0 {
		rule.DstPort = set.NewPortSet()
		for _, port := range rc.DstPort {
			rule.DstPort.Add(port)
		}
	}

	action, err := ParseAction(rc.Action)
	if err != nil {
		return nil, fmt.Errorf("invalid action %s: %w", rc.Action, err)
	}
	rule.Action = action

	if len(rc.SrcNet) > 0 {
		rule.SrcNet = set.NewIPSet()
		for _, srcNet := range rc.SrcNet {
			_, ipnet, err := net.ParseCIDR(srcNet)
			if err != nil {
				return nil, fmt.Errorf("invalid source net %s: %w", srcNet, err)
			}
			rule.SrcNet.Add(ipnet)
		}
	}

	if len(rc.DstNet) > 0 {
		rule.DstNet = set.NewIPSet()
		for _, dstNet := range rc.DstNet {
			_, ipnet, err := net.ParseCIDR(dstNet)
			if err != nil {
				return nil, fmt.Errorf("invalid destination net %s: %w", dstNet, err)
			}
			rule.DstNet.Add(ipnet)
		}
	}

	return rule, nil
}

func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("CIDR %s is invalid", cidr))
	}
	return ipnet
}
