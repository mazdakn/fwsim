package rule

import (
	"fmt"
	"net"
	"strings"

	"github.com/mazdakn/fwsim/pkg/counter"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/set"
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

func WithProto(p proto.Proto) RuleOption {
	return func(r *Rule) {
		if r.Proto == nil {
			r.Proto = set.NewProtoSet()
		}
		r.Proto.Add(p)
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

func WithNegProto(p proto.Proto) RuleOption {
	return func(r *Rule) {
		if r.NegProto == nil {
			r.NegProto = set.NewProtoSet()
		}
		r.NegProto.Add(p)
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

func WithSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.SrcIPSet = s
	}
}

func WithDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.DstIPSet = s
	}
}

func WithSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.SrcPortSet = s
	}
}

func WithDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.DstPortSet = s
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

	// User-defined named sets for matching.
	SrcIPSet   set.Set
	DstIPSet   set.Set
	SrcPortSet set.Set
	DstPortSet set.Set

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
	if r.SrcIPSet != nil && !r.SrcIPSet.Match(pkt.SrcAddr) {
		return false
	}
	if r.DstIPSet != nil && !r.DstIPSet.Match(pkt.DstAddr) {
		return false
	}
	if r.SrcPortSet != nil && !r.SrcPortSet.Match(pkt.SrcPort) {
		return false
	}
	if r.DstPortSet != nil && !r.DstPortSet.Match(pkt.DstPort) {
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
	if r.SrcPortSet != nil {
		if st, ok := r.SrcPortSet.(fmt.Stringer); ok {
			if srcPort == "*" {
				srcPort = st.String()
			} else {
				srcPort = srcPort + "," + st.String()
			}
		}
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
	if r.DstPortSet != nil {
		if st, ok := r.DstPortSet.(fmt.Stringer); ok {
			if dstPort == "*" {
				dstPort = st.String()
			} else {
				dstPort = dstPort + "," + st.String()
			}
		}
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
	if r.SrcIPSet != nil {
		if st, ok := r.SrcIPSet.(fmt.Stringer); ok {
			if srcNet == "*" {
				srcNet = st.String()
			} else {
				srcNet = srcNet + "," + st.String()
			}
		}
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
	if r.DstIPSet != nil {
		if st, ok := r.DstIPSet.(fmt.Stringer); ok {
			if dstNet == "*" {
				dstNet = st.String()
			} else {
				dstNet = dstNet + "," + st.String()
			}
		}
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
