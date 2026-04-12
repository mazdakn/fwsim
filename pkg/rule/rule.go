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
		if r.Destination.Port == nil {
			r.Destination.Port = set.NewPortSet()
		}
		r.Destination.Port.Add(port)
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
		if r.Destination.Net == nil {
			r.Destination.Net = set.NewIPSet()
		}
		r.Destination.Net.Add(MustParseCIDR(cidr))
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
		if r.NegSource.Port == nil {
			r.NegSource.Port = set.NewPortSet()
		}
		r.NegSource.Port.Add(port)
	}
}

func WithNegDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.NegDestination.Port == nil {
			r.NegDestination.Port = set.NewPortSet()
		}
		r.NegDestination.Port.Add(port)
	}
}

func WithNegSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.NegSource.Net == nil {
			r.NegSource.Net = set.NewIPSet()
		}
		r.NegSource.Net.Add(MustParseCIDR(cidr))
	}
}

func WithNegDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.NegDestination.Net == nil {
			r.NegDestination.Net = set.NewIPSet()
		}
		r.NegDestination.Net.Add(MustParseCIDR(cidr))
	}
}

func WithSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Source.IPSet = s
	}
}

func WithDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Destination.IPSet = s
	}
}

func WithSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Source.PortSet = s
	}
}

func WithDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Destination.PortSet = s
	}
}

func WithNegSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NegSource.IPSet = s
	}
}

func WithNegDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NegDestination.IPSet = s
	}
}

func WithNegSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NegSource.PortSet = s
	}
}

func WithNegDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NegDestination.PortSet = s
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
	Name        string
	Order       uint64
	Source      Endpoint
	Destination Endpoint
	Proto       *set.ProtoSet

	NegSource      Endpoint
	NegDestination Endpoint
	NegProto       *set.ProtoSet

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
	if r.NegSource.Port != nil && r.NegSource.Port.Match(pkt.SrcPort) {
		return false
	}
	if r.Destination.Port != nil && !r.Destination.Port.Match(pkt.DstPort) {
		return false
	}
	if r.NegDestination.Port != nil && r.NegDestination.Port.Match(pkt.DstPort) {
		return false
	}
	if r.Source.Net != nil && !r.Source.Net.Match(pkt.SrcAddr) {
		return false
	}
	if r.NegSource.Net != nil && r.NegSource.Net.Match(pkt.SrcAddr) {
		return false
	}
	if r.Destination.Net != nil && !r.Destination.Net.Match(pkt.DstAddr) {
		return false
	}
	if r.NegDestination.Net != nil && r.NegDestination.Net.Match(pkt.DstAddr) {
		return false
	}
	if !matchNamedSet(r.Source.IPSet, pkt.SrcAddr) {
		return false
	}
	if !matchNamedSet(r.Destination.IPSet, pkt.DstAddr) {
		return false
	}
	if !matchNamedSet(r.Source.PortSet, pkt.SrcPort) {
		return false
	}
	if !matchNamedSet(r.Destination.PortSet, pkt.DstPort) {
		return false
	}
	if r.NegSource.IPSet != nil && r.NegSource.IPSet.Match(pkt.SrcAddr) {
		return false
	}
	if r.NegDestination.IPSet != nil && r.NegDestination.IPSet.Match(pkt.DstAddr) {
		return false
	}
	if r.NegSource.PortSet != nil && r.NegSource.PortSet.Match(pkt.SrcPort) {
		return false
	}
	if r.NegDestination.PortSet != nil && r.NegDestination.PortSet.Match(pkt.DstPort) {
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
	case r.Source.Port != nil && r.NegSource.Port != nil:
		srcPort = r.Source.Port.String() + ",!" + r.NegSource.Port.String()
	case r.Source.Port != nil:
		srcPort = r.Source.Port.String()
	case r.NegSource.Port != nil:
		srcPort = "!" + r.NegSource.Port.String()
	}
	srcPort = appendSetString(srcPort, r.Source.PortSet)
	srcPort = appendNegSetString(srcPort, r.NegSource.PortSet)

	dstPort := "*"
	switch {
	case r.Destination.Port != nil && r.NegDestination.Port != nil:
		dstPort = r.Destination.Port.String() + ",!" + r.NegDestination.Port.String()
	case r.Destination.Port != nil:
		dstPort = r.Destination.Port.String()
	case r.NegDestination.Port != nil:
		dstPort = "!" + r.NegDestination.Port.String()
	}
	dstPort = appendSetString(dstPort, r.Destination.PortSet)
	dstPort = appendNegSetString(dstPort, r.NegDestination.PortSet)

	srcNet := "*"
	switch {
	case r.Source.Net != nil && r.NegSource.Net != nil:
		srcNet = r.Source.Net.String() + ",!" + r.NegSource.Net.String()
	case r.Source.Net != nil:
		srcNet = r.Source.Net.String()
	case r.NegSource.Net != nil:
		srcNet = "!" + r.NegSource.Net.String()
	}
	srcNet = appendSetString(srcNet, r.Source.IPSet)
	srcNet = appendNegSetString(srcNet, r.NegSource.IPSet)

	dstNet := "*"
	switch {
	case r.Destination.Net != nil && r.NegDestination.Net != nil:
		dstNet = r.Destination.Net.String() + ",!" + r.NegDestination.Net.String()
	case r.Destination.Net != nil:
		dstNet = r.Destination.Net.String()
	case r.NegDestination.Net != nil:
		dstNet = "!" + r.NegDestination.Net.String()
	}
	dstNet = appendSetString(dstNet, r.Destination.IPSet)
	dstNet = appendNegSetString(dstNet, r.NegDestination.IPSet)
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
