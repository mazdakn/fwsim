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
		_ = r.Proto.Add(p)
	}
}

func WithSrcPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.Source.Port == nil {
			r.Source.Port = set.NewPortSet()
		}
		_ = r.Source.Port.Add(port)
	}
}

func WithDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.Destination.Port == nil {
			r.Destination.Port = set.NewPortSet()
		}
		_ = r.Destination.Port.Add(port)
	}
}

func WithSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.Source.Net == nil {
			r.Source.Net = set.NewIPSet()
		}
		_ = r.Source.Net.Add(MustParseCIDR(cidr))
	}
}

func WithDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.Destination.Net == nil {
			r.Destination.Net = set.NewIPSet()
		}
		_ = r.Destination.Net.Add(MustParseCIDR(cidr))
	}
}

func WithNotProto(p proto.Proto) RuleOption {
	return func(r *Rule) {
		if r.NotProto == nil {
			r.NotProto = set.NewProtoSet()
		}
		_ = r.NotProto.Add(p)
	}
}

func WithNotSrcPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.NotSource.Port == nil {
			r.NotSource.Port = set.NewPortSet()
		}
		_ = r.NotSource.Port.Add(port)
	}
}

func WithNotDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.NotDestination.Port == nil {
			r.NotDestination.Port = set.NewPortSet()
		}
		_ = r.NotDestination.Port.Add(port)
	}
}

func WithNotSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.NotSource.Net == nil {
			r.NotSource.Net = set.NewIPSet()
		}
		_ = r.NotSource.Net.Add(MustParseCIDR(cidr))
	}
}

func WithNotDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.NotDestination.Net == nil {
			r.NotDestination.Net = set.NewIPSet()
		}
		_ = r.NotDestination.Net.Add(MustParseCIDR(cidr))
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

func WithNotSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotSource.IPSet = s
	}
}

func WithNotDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotDestination.IPSet = s
	}
}

func WithNotSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotSource.PortSet = s
	}
}

func WithNotDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotDestination.PortSet = s
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

	NotSource      Endpoint
	NotDestination Endpoint
	NotProto       *set.ProtoSet

	Action Action

	packetCount *counter.Counter
}

func (r *Rule) Match(pkt *packet.Packet) bool {
	if r.Proto != nil && !r.Proto.Match(pkt.Proto) {
		return false
	}
	if r.NotProto != nil && r.NotProto.Match(pkt.Proto) {
		return false
	}
	if r.Source.Port != nil && !r.Source.Port.Match(pkt.SrcPort) {
		return false
	}
	if r.NotSource.Port != nil && r.NotSource.Port.Match(pkt.SrcPort) {
		return false
	}
	if r.Destination.Port != nil && !r.Destination.Port.Match(pkt.DstPort) {
		return false
	}
	if r.NotDestination.Port != nil && r.NotDestination.Port.Match(pkt.DstPort) {
		return false
	}
	if r.Source.Net != nil && !r.Source.Net.Match(pkt.SrcAddr) {
		return false
	}
	if r.NotSource.Net != nil && r.NotSource.Net.Match(pkt.SrcAddr) {
		return false
	}
	if r.Destination.Net != nil && !r.Destination.Net.Match(pkt.DstAddr) {
		return false
	}
	if r.NotDestination.Net != nil && r.NotDestination.Net.Match(pkt.DstAddr) {
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
	if r.NotSource.IPSet != nil && r.NotSource.IPSet.Match(pkt.SrcAddr) {
		return false
	}
	if r.NotDestination.IPSet != nil && r.NotDestination.IPSet.Match(pkt.DstAddr) {
		return false
	}
	if r.NotSource.PortSet != nil && r.NotSource.PortSet.Match(pkt.SrcPort) {
		return false
	}
	if r.NotDestination.PortSet != nil && r.NotDestination.PortSet.Match(pkt.DstPort) {
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
	case r.Proto != nil && r.NotProto != nil:
		proto = r.Proto.String() + ",!" + r.NotProto.String()
	case r.Proto != nil:
		proto = r.Proto.String()
	case r.NotProto != nil:
		proto = "!" + r.NotProto.String()
	}
	srcPort := "*"
	switch {
	case r.Source.Port != nil && r.NotSource.Port != nil:
		srcPort = r.Source.Port.String() + ",!" + r.NotSource.Port.String()
	case r.Source.Port != nil:
		srcPort = r.Source.Port.String()
	case r.NotSource.Port != nil:
		srcPort = "!" + r.NotSource.Port.String()
	}
	srcPort = appendSetString(srcPort, r.Source.PortSet)
	srcPort = appendNotSetString(srcPort, r.NotSource.PortSet)

	dstPort := "*"
	switch {
	case r.Destination.Port != nil && r.NotDestination.Port != nil:
		dstPort = r.Destination.Port.String() + ",!" + r.NotDestination.Port.String()
	case r.Destination.Port != nil:
		dstPort = r.Destination.Port.String()
	case r.NotDestination.Port != nil:
		dstPort = "!" + r.NotDestination.Port.String()
	}
	dstPort = appendSetString(dstPort, r.Destination.PortSet)
	dstPort = appendNotSetString(dstPort, r.NotDestination.PortSet)

	srcNet := "*"
	switch {
	case r.Source.Net != nil && r.NotSource.Net != nil:
		srcNet = r.Source.Net.String() + ",!" + r.NotSource.Net.String()
	case r.Source.Net != nil:
		srcNet = r.Source.Net.String()
	case r.NotSource.Net != nil:
		srcNet = "!" + r.NotSource.Net.String()
	}
	srcNet = appendSetString(srcNet, r.Source.IPSet)
	srcNet = appendNotSetString(srcNet, r.NotSource.IPSet)

	dstNet := "*"
	switch {
	case r.Destination.Net != nil && r.NotDestination.Net != nil:
		dstNet = r.Destination.Net.String() + ",!" + r.NotDestination.Net.String()
	case r.Destination.Net != nil:
		dstNet = r.Destination.Net.String()
	case r.NotDestination.Net != nil:
		dstNet = "!" + r.NotDestination.Net.String()
	}
	dstNet = appendSetString(dstNet, r.Destination.IPSet)
	dstNet = appendNotSetString(dstNet, r.NotDestination.IPSet)
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

// appendNotSetString is like appendSetString but prefixes the set string with
// "!" to indicate a negated match constraint.
func appendNotSetString(base string, s set.Set) string {
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
