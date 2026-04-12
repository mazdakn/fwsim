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
		if r.Source.Port == nil {
			r.Source.Port = set.NewPortSet()
		}
		r.Source.Port.Add(port)
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
		if r.Source.Net == nil {
			r.Source.Net = set.NewIPSet()
		}
		r.Source.Net.Add(MustParseCIDR(cidr))
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
		r.Source.IPSet = s
	}
}

func WithDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.DstIPSet = s
	}
}

func WithSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Source.PortSet = s
	}
}

func WithDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.DstPortSet = s
	}
}

func WithNegSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NegSrcIPSet = s
	}
}

func WithNegDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NegDstIPSet = s
	}
}

func WithNegSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NegSrcPortSet = s
	}
}

func WithNegDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NegDstPortSet = s
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

// Endpoint groups the network and port match criteria for one traffic direction.
type Endpoint struct {
	Net     *set.IPSet
	Port    *set.PortSet
	IPSet   set.Set
	PortSet set.Set
}

type Rule struct {
	Name   string
	Order  uint64
	Source Endpoint
	DstNet *set.IPSet
	Proto  *set.ProtoSet

	DstPort *set.PortSet

	NegSrcNet  *set.IPSet
	NegDstNet  *set.IPSet
	NegProto   *set.ProtoSet
	NegSrcPort *set.PortSet
	NegDstPort *set.PortSet

	// User-defined named sets for matching.
	DstIPSet   set.Set
	DstPortSet set.Set

	// User-defined named sets for negated matching.
	NegSrcIPSet   set.Set
	NegDstIPSet   set.Set
	NegSrcPortSet set.Set
	NegDstPortSet set.Set

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
	if r.Source.Port != nil && !r.Source.Port.Match(pkt.SrcPort) {
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
	if r.Source.Net != nil && !r.Source.Net.Match(pkt.SrcAddr) {
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
	if !matchNamedSet(r.Source.IPSet, pkt.SrcAddr) {
		return false
	}
	if !matchNamedSet(r.DstIPSet, pkt.DstAddr) {
		return false
	}
	if !matchNamedSet(r.Source.PortSet, pkt.SrcPort) {
		return false
	}
	if !matchNamedSet(r.DstPortSet, pkt.DstPort) {
		return false
	}
	if r.NegSrcIPSet != nil && r.NegSrcIPSet.Match(pkt.SrcAddr) {
		return false
	}
	if r.NegDstIPSet != nil && r.NegDstIPSet.Match(pkt.DstAddr) {
		return false
	}
	if r.NegSrcPortSet != nil && r.NegSrcPortSet.Match(pkt.SrcPort) {
		return false
	}
	if r.NegDstPortSet != nil && r.NegDstPortSet.Match(pkt.DstPort) {
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
	case r.Source.Port != nil && r.NegSrcPort != nil:
		srcPort = r.Source.Port.String() + ",!" + r.NegSrcPort.String()
	case r.Source.Port != nil:
		srcPort = r.Source.Port.String()
	case r.NegSrcPort != nil:
		srcPort = "!" + r.NegSrcPort.String()
	}
	srcPort = appendSetString(srcPort, r.Source.PortSet)
	srcPort = appendNegSetString(srcPort, r.NegSrcPortSet)

	dstPort := "*"
	switch {
	case r.DstPort != nil && r.NegDstPort != nil:
		dstPort = r.DstPort.String() + ",!" + r.NegDstPort.String()
	case r.DstPort != nil:
		dstPort = r.DstPort.String()
	case r.NegDstPort != nil:
		dstPort = "!" + r.NegDstPort.String()
	}
	dstPort = appendSetString(dstPort, r.DstPortSet)
	dstPort = appendNegSetString(dstPort, r.NegDstPortSet)

	srcNet := "*"
	switch {
	case r.Source.Net != nil && r.NegSrcNet != nil:
		srcNet = r.Source.Net.String() + ",!" + r.NegSrcNet.String()
	case r.Source.Net != nil:
		srcNet = r.Source.Net.String()
	case r.NegSrcNet != nil:
		srcNet = "!" + r.NegSrcNet.String()
	}
	srcNet = appendSetString(srcNet, r.Source.IPSet)
	srcNet = appendNegSetString(srcNet, r.NegSrcIPSet)

	dstNet := "*"
	switch {
	case r.DstNet != nil && r.NegDstNet != nil:
		dstNet = r.DstNet.String() + ",!" + r.NegDstNet.String()
	case r.DstNet != nil:
		dstNet = r.DstNet.String()
	case r.NegDstNet != nil:
		dstNet = "!" + r.NegDstNet.String()
	}
	dstNet = appendSetString(dstNet, r.DstIPSet)
	dstNet = appendNegSetString(dstNet, r.NegDstIPSet)
	return fmt.Sprintf("%s %s{%s:%s->%s:%s}", r.Action, proto, srcNet, srcPort, dstNet, dstPort)
}

// matchNamedSet returns true if s is nil (no constraint) or if s matches v.
func matchNamedSet(s set.Set, v any) bool {
	if s == nil {
		return true
	}
	return s.Match(v)
}

// appendSetString appends the string representation of s to base, separated
// by a comma.  If base is "*" (wildcard), s replaces it entirely.
// If s does not implement fmt.Stringer, base is returned unchanged.
func appendSetString(base string, s set.Set) string {
	if s == nil {
		return base
	}
	st, ok := s.(fmt.Stringer)
	if !ok {
		return base
	}
	if base == "*" {
		return st.String()
	}
	return base + "," + st.String()
}

// appendNegSetString is like appendSetString but prefixes the set string with
// "!" to indicate a negated match constraint.
func appendNegSetString(base string, s set.Set) string {
	if s == nil {
		return base
	}
	st, ok := s.(fmt.Stringer)
	if !ok {
		return base
	}
	neg := "!" + st.String()
	if base == "*" {
		return neg
	}
	return base + "," + neg
}

func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("CIDR %s is invalid", cidr))
	}
	return ipnet
}
