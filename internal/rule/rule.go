package rule

import (
	"fmt"
	"net"
	"strings"

	"github.com/mazdakn/fwsim/internal/counter"
	"github.com/mazdakn/fwsim/internal/packet"
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

// ParseAction parses an action string into an Action type
func MustParseAction(s string) Action {
	switch strings.ToLower(s) {
	case "accept":
		return Accept
	case "drop":
		return Drop
	default:
		panic(fmt.Sprintf("unknown action: %s", s))
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

func WithNegProto(proto uint8) RuleOption {
	return func(r *Rule) {
		if r.NegProto == nil {
			r.NegProto = set.NewProtoSet()
		}
		r.NegProto.Add(proto)
	}
}

func WithNegSrcPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.NegSrcPort == nil {
			r.NegSrcPort = set.NewPortSet()
		}
		r.NegSrcPort.Add(port)
	}
}

func WithNegDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.NegDstPort == nil {
			r.NegDstPort = set.NewPortSet()
		}
		r.NegDstPort.Add(port)
	}
}

func WithNegSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.NegSrcNet == nil {
			r.NegSrcNet = set.NewIPSet()
		}
		r.NegSrcNet.Add(MustParseCIDR(cidr))
	}
}

func WithNegDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.NegDstNet == nil {
			r.NegDstNet = set.NewIPSet()
		}
		r.NegDstNet.Add(MustParseCIDR(cidr))
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

func New(opts ...RuleOption) *Rule {
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

	NegSrcNet  *set.IPSet
	NegDstNet  *set.IPSet
	NegProto   *set.ProtoSet
	NegSrcPort *set.PortSet
	NegDstPort *set.PortSet

	Action Action

	packetCount *counter.Counter
}

func (r *Rule) Match(pkt *packet.Packet) bool {
	if r.Proto != nil && !r.Proto.Match(pkt.Proto) {
		return false
	}
	if r.NegProto != nil && r.NegProto.Match(pkt.Proto) {
		return false
	}
	if r.SrcPort != nil && !r.SrcPort.Match(pkt.SrcPort) {
		return false
	}
	if r.NegSrcPort != nil && r.NegSrcPort.Match(pkt.SrcPort) {
		return false
	}
	if r.DstPort != nil && !r.DstPort.Match(pkt.DstPort) {
		return false
	}
	if r.NegDstPort != nil && r.NegDstPort.Match(pkt.DstPort) {
		return false
	}
	if r.SrcNet != nil && !r.SrcNet.Match(pkt.SrcAddr) {
		return false
	}
	if r.NegSrcNet != nil && r.NegSrcNet.Match(pkt.SrcAddr) {
		return false
	}
	if r.DstNet != nil && !r.DstNet.Match(pkt.DstAddr) {
		return false
	}
	if r.NegDstNet != nil && r.NegDstNet.Match(pkt.DstAddr) {
		return false
	}
	// All conditions passed - increment packet counter
	r.packetCount.Increment()
	return true
}

func (r *Rule) PacketCount() uint64 {
	return r.packetCount.Get()
}

func (r *Rule) IncrementPacketCount() {
	r.packetCount.Increment()
}

func (r *Rule) ResetPacketCount() {
	r.packetCount.Reset()
}

func (r *Rule) String() string {
	if r.Name != "" {
		return r.Name
	}
	proto := "*"
	switch {
	case r.Proto != nil && r.NegProto != nil:
		proto = r.Proto.String() + ",!" + r.NegProto.String()
	case r.Proto != nil:
		proto = r.Proto.String()
	case r.NegProto != nil:
		proto = "!" + r.NegProto.String()
	}
	srcPort := "*"
	switch {
	case r.SrcPort != nil && r.NegSrcPort != nil:
		srcPort = r.SrcPort.String() + ",!" + r.NegSrcPort.String()
	case r.SrcPort != nil:
		srcPort = r.SrcPort.String()
	case r.NegSrcPort != nil:
		srcPort = "!" + r.NegSrcPort.String()
	}
	dstPort := "*"
	switch {
	case r.DstPort != nil && r.NegDstPort != nil:
		dstPort = r.DstPort.String() + ",!" + r.NegDstPort.String()
	case r.DstPort != nil:
		dstPort = r.DstPort.String()
	case r.NegDstPort != nil:
		dstPort = "!" + r.NegDstPort.String()
	}
	srcNet := "*"
	switch {
	case r.SrcNet != nil && r.NegSrcNet != nil:
		srcNet = r.SrcNet.String() + ",!" + r.NegSrcNet.String()
	case r.SrcNet != nil:
		srcNet = r.SrcNet.String()
	case r.NegSrcNet != nil:
		srcNet = "!" + r.NegSrcNet.String()
	}
	dstNet := "*"
	switch {
	case r.DstNet != nil && r.NegDstNet != nil:
		dstNet = r.DstNet.String() + ",!" + r.NegDstNet.String()
	case r.DstNet != nil:
		dstNet = r.DstNet.String()
	case r.NegDstNet != nil:
		dstNet = "!" + r.NegDstNet.String()
	}
	return fmt.Sprintf("%s %s{%s:%s->%s:%s}", r.Action, proto, srcNet, srcPort, dstNet, dstPort)
}

// RuleConfig is the YAML configuration structure for a single firewall rule.
type RuleConfig struct {
	Name       string   `yaml:"name,omitempty"`
	Order      uint64   `yaml:"order,omitempty"`
	SrcNet     []string `yaml:"src_net,omitempty"      validate:"isValidCIDR"`
	DstNet     []string `yaml:"dst_net,omitempty"      validate:"isValidCIDR"`
	Protocol   []uint8  `yaml:"proto,omitempty"        validate:"isProtoValid"`
	SrcPort    []uint16 `yaml:"src_port,omitempty"     validate:"isPortValid"`
	DstPort    []uint16 `yaml:"dst_port,omitempty"     validate:"isPortValid"`
	NegSrcNet  []string `yaml:"neg_src_net,omitempty"  validate:"isValidCIDR"`
	NegDstNet  []string `yaml:"neg_dst_net,omitempty"  validate:"isValidCIDR"`
	NegProto   []uint8  `yaml:"neg_proto,omitempty"    validate:"isProtoValid"`
	NegSrcPort []uint16 `yaml:"neg_src_port,omitempty" validate:"isPortValid"`
	NegDstPort []uint16 `yaml:"neg_dst_port,omitempty" validate:"isPortValid"`
	Action     string   `yaml:"action,omitempty"       validate:"isValidAction"`
}

// ToRule converts a RuleConfig into a Rule domain object.
func (rc *RuleConfig) ToRule() (*Rule, error) {
	action, err := ParseAction(rc.Action)
	if err != nil {
		return nil, err
	}
	opts := []RuleOption{WithAction(action), WithName(rc.Name), WithOrder(rc.Order)}
	for _, proto := range rc.Protocol {
		opts = append(opts, WithProto(proto))
	}
	for _, proto := range rc.NegProto {
		opts = append(opts, WithNegProto(proto))
	}
	for _, port := range rc.SrcPort {
		opts = append(opts, WithSrcPort(port))
	}
	for _, port := range rc.NegSrcPort {
		opts = append(opts, WithNegSrcPort(port))
	}
	for _, port := range rc.DstPort {
		opts = append(opts, WithDstPort(port))
	}
	for _, port := range rc.NegDstPort {
		opts = append(opts, WithNegDstPort(port))
	}
	for _, net := range rc.SrcNet {
		opts = append(opts, WithSrcNet(net))
	}
	for _, net := range rc.NegSrcNet {
		opts = append(opts, WithNegSrcNet(net))
	}
	for _, net := range rc.DstNet {
		opts = append(opts, WithDstNet(net))
	}
	for _, net := range rc.NegDstNet {
		opts = append(opts, WithNegDstNet(net))
	}
	return New(opts...), nil
}

func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("CIDR %s is invalid", cidr))
	}
	return ipnet
}
