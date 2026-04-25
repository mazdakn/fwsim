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
	Pass
)

func (a *Action) String() string {
	if a == nil {
		return "no match"
	}
	switch *a {
	case Accept:
		return "Accept"
	case Drop:
		return "Drop"
	case Pass:
		return "Pass"
	default:
		return fmt.Sprintf("Undefined(%d)", *a)
	}
}

func (a Action) Validate() error {
	switch a {
	case Accept, Drop, Pass:
		return nil
	default:
		return fmt.Errorf("undefined action %v", &a)
	}
}

// ParseAction parses an action string into an Action type
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "accept":
		return Accept, nil
	case "drop":
		return Drop, nil
	case "pass":
		return Pass, nil
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
	case "pass":
		return Pass
	default:
		panic(fmt.Sprintf("unknown action: %s", s))
	}
}

type RuleOption func(*Rule)

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

// Protocol options.

func WithProto(p proto.Proto) RuleOption {
	return func(r *Rule) {
		if r.Proto == nil {
			r.Proto = set.NewProtoSet()
		}
		if err := r.Proto.Add(p); err != nil {
			panic(fmt.Sprintf("invalid protocol %v", p))
		}
	}
}

func WithNotProto(p proto.Proto) RuleOption {
	return func(r *Rule) {
		if r.NotProto == nil {
			r.NotProto = set.NewProtoSet()
		}
		if err := r.NotProto.Add(p); err != nil {
			panic(fmt.Sprintf("invalid protocol %v", p))
		}
	}
}

// Source port options.

func WithSrcPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.Source.Port == nil {
			r.Source.Port = set.NewPortSet()
		}
		if err := r.Source.Port.Add(port); err != nil {
			panic(fmt.Sprintf("invalid port %d", port))
		}
	}
}

func WithNotSrcPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.NotSource.Port == nil {
			r.NotSource.Port = set.NewPortSet()
		}
		if err := r.NotSource.Port.Add(port); err != nil {
			panic(fmt.Sprintf("invalid port %d", port))
		}
	}
}

func WithSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Source.Sets = append(r.Source.Sets, s)
	}
}

func WithNotSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotSource.Sets = append(r.NotSource.Sets, s)
	}
}

func WithSrcIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Source.Sets = append(r.Source.Sets, s)
	}
}

func WithNotSrcIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotSource.Sets = append(r.NotSource.Sets, s)
	}
}

// Destination port options.

func WithDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.Destination.Port == nil {
			r.Destination.Port = set.NewPortSet()
		}
		if err := r.Destination.Port.Add(port); err != nil {
			panic(fmt.Sprintf("invalid port %d", port))
		}
	}
}

func WithNotDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		if r.NotDestination.Port == nil {
			r.NotDestination.Port = set.NewPortSet()
		}
		if err := r.NotDestination.Port.Add(port); err != nil {
			panic(fmt.Sprintf("invalid port %d", port))
		}
	}
}

func WithDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Destination.Sets = append(r.Destination.Sets, s)
	}
}

func WithNotDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotDestination.Sets = append(r.NotDestination.Sets, s)
	}
}

func WithDstIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Destination.Sets = append(r.Destination.Sets, s)
	}
}

func WithNotDstIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotDestination.Sets = append(r.NotDestination.Sets, s)
	}
}

// Source address options.

func WithSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.Source.Net == nil {
			r.Source.Net = set.NewIPSet()
		}
		if err := r.Source.Net.Add(MustParseCIDR(cidr)); err != nil {
			panic(fmt.Sprintf("invalid cidr %s", cidr))
		}
	}
}

func WithNotSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.NotSource.Net == nil {
			r.NotSource.Net = set.NewIPSet()
		}
		if err := r.NotSource.Net.Add(MustParseCIDR(cidr)); err != nil {
			panic(fmt.Sprintf("invalid cidr %s", cidr))
		}
	}
}

func WithSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Source.Sets = append(r.Source.Sets, s)
	}
}

func WithNotSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotSource.Sets = append(r.NotSource.Sets, s)
	}
}

// Source address options.

func WithDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.Destination.Net == nil {
			r.Destination.Net = set.NewIPSet()
		}
		if err := r.Destination.Net.Add(MustParseCIDR(cidr)); err != nil {
			panic(fmt.Sprintf("invalid cidr %s", cidr))
		}
	}
}

func WithNotDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		if r.NotDestination.Net == nil {
			r.NotDestination.Net = set.NewIPSet()
		}
		if err := r.NotDestination.Net.Add(MustParseCIDR(cidr)); err != nil {
			panic(fmt.Sprintf("invalid cidr %s", cidr))
		}
	}
}

func WithDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Destination.Sets = append(r.Destination.Sets, s)
	}
}

func WithNotDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotDestination.Sets = append(r.NotDestination.Sets, s)
	}
}

// Ingress interface options.

func WithIngressIface(iface string) RuleOption {
	return func(r *Rule) {
		r.IngressIface = append(r.IngressIface, iface)
	}
}

func WithNotIngressIface(iface string) RuleOption {
	return func(r *Rule) {
		r.NotIngressIface = append(r.NotIngressIface, iface)
	}
}

// Egress interface options.

func WithEgressIface(iface string) RuleOption {
	return func(r *Rule) {
		r.EgressIface = append(r.EgressIface, iface)
	}
}

func WithNotEgressIface(iface string) RuleOption {
	return func(r *Rule) {
		r.NotEgressIface = append(r.NotEgressIface, iface)
	}
}

func WithSrcIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Source.Sets = append(r.Source.Sets, s)
	}
}

func WithNotSrcIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotSource.Sets = append(r.NotSource.Sets, s)
	}
}

func WithDstIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.Destination.Sets = append(r.Destination.Sets, s)
	}
}

func WithNotDstIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) {
		r.NotDestination.Sets = append(r.NotDestination.Sets, s)
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
	Net  *set.IPSet
	Port *set.PortSet
	Sets []set.Set
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

	IngressIface    []string
	NotIngressIface []string

	EgressIface    []string
	NotEgressIface []string

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
	srcIPPort := set.IPPortTuple{IP: pkt.SrcAddr, Port: pkt.SrcPort}
	dstIPPort := set.IPPortTuple{IP: pkt.DstAddr, Port: pkt.DstPort}
	if !matchAllNamedSets(r.Source.Sets, pkt.SrcAddr, pkt.SrcPort, srcIPPort, pkt.Metadata.IngressIface) {
		return false
	}
	if !matchAllNamedSets(r.Destination.Sets, pkt.DstAddr, pkt.DstPort, dstIPPort, pkt.Metadata.EgressIface) {
		return false
	}
	if matchAnyNamedSet(r.NotSource.Sets, pkt.SrcAddr, pkt.SrcPort, srcIPPort, pkt.Metadata.IngressIface) {
		return false
	}
	if matchAnyNamedSet(r.NotDestination.Sets, pkt.DstAddr, pkt.DstPort, dstIPPort, pkt.Metadata.EgressIface) {
		return false
	}
	if len(r.IngressIface) > 0 && !containsString(r.IngressIface, pkt.Metadata.IngressIface) {
		return false
	}
	if len(r.NotIngressIface) > 0 && containsString(r.NotIngressIface, pkt.Metadata.IngressIface) {
		return false
	}
	if len(r.EgressIface) > 0 && !containsString(r.EgressIface, pkt.Metadata.EgressIface) {
		return false
	}
	if len(r.NotEgressIface) > 0 && containsString(r.NotEgressIface, pkt.Metadata.EgressIface) {
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
	srcPort = appendSetStrings(srcPort, filterEndpointSetsByType(r.Source.Sets, set.TypePort))
	srcPort = appendSetStrings(srcPort, filterEndpointSetsByType(r.Source.Sets, set.TypeIPPort))
	srcPort = appendNotSetStrings(srcPort, filterEndpointSetsByType(r.NotSource.Sets, set.TypePort))
	srcPort = appendNotSetStrings(srcPort, filterEndpointSetsByType(r.NotSource.Sets, set.TypeIPPort))

	dstPort := "*"
	switch {
	case r.Destination.Port != nil && r.NotDestination.Port != nil:
		dstPort = r.Destination.Port.String() + ",!" + r.NotDestination.Port.String()
	case r.Destination.Port != nil:
		dstPort = r.Destination.Port.String()
	case r.NotDestination.Port != nil:
		dstPort = "!" + r.NotDestination.Port.String()
	}
	dstPort = appendSetStrings(dstPort, filterEndpointSetsByType(r.Destination.Sets, set.TypePort))
	dstPort = appendSetStrings(dstPort, filterEndpointSetsByType(r.Destination.Sets, set.TypeIPPort))
	dstPort = appendNotSetStrings(dstPort, filterEndpointSetsByType(r.NotDestination.Sets, set.TypePort))
	dstPort = appendNotSetStrings(dstPort, filterEndpointSetsByType(r.NotDestination.Sets, set.TypeIPPort))

	srcNet := "*"
	switch {
	case r.Source.Net != nil && r.NotSource.Net != nil:
		srcNet = r.Source.Net.String() + ",!" + r.NotSource.Net.String()
	case r.Source.Net != nil:
		srcNet = r.Source.Net.String()
	case r.NotSource.Net != nil:
		srcNet = "!" + r.NotSource.Net.String()
	}
	srcNet = appendSetStrings(srcNet, filterEndpointSetsByType(r.Source.Sets, set.TypeIP))
	srcNet = appendNotSetStrings(srcNet, filterEndpointSetsByType(r.NotSource.Sets, set.TypeIP))

	dstNet := "*"
	switch {
	case r.Destination.Net != nil && r.NotDestination.Net != nil:
		dstNet = r.Destination.Net.String() + ",!" + r.NotDestination.Net.String()
	case r.Destination.Net != nil:
		dstNet = r.Destination.Net.String()
	case r.NotDestination.Net != nil:
		dstNet = "!" + r.NotDestination.Net.String()
	}
	dstNet = appendSetStrings(dstNet, filterEndpointSetsByType(r.Destination.Sets, set.TypeIP))
	dstNet = appendNotSetStrings(dstNet, filterEndpointSetsByType(r.NotDestination.Sets, set.TypeIP))

	base := fmt.Sprintf("%s %s{%s:%s->%s:%s}", &r.Action, proto, srcNet, srcPort, dstNet, dstPort)

	ingressIfaceSets := filterEndpointSetsByType(r.Source.Sets, set.TypeIface)
	notIngressIfaceSets := filterEndpointSetsByType(r.NotSource.Sets, set.TypeIface)
	egressIfaceSets := filterEndpointSetsByType(r.Destination.Sets, set.TypeIface)
	notEgressIfaceSets := filterEndpointSetsByType(r.NotDestination.Sets, set.TypeIface)

	if len(r.IngressIface) > 0 || len(r.NotIngressIface) > 0 || len(ingressIfaceSets) > 0 || len(notIngressIfaceSets) > 0 {
		iface := strings.Join(r.IngressIface, ",")
		for _, v := range r.NotIngressIface {
			if iface != "" {
				iface += ","
			}
			iface += "!" + v
		}
		iface = appendSetStrings(iface, ingressIfaceSets)
		iface = appendNotSetStrings(iface, notIngressIfaceSets)
		base += " ingress_iface=" + iface
	}
	if len(r.EgressIface) > 0 || len(r.NotEgressIface) > 0 || len(egressIfaceSets) > 0 || len(notEgressIfaceSets) > 0 {
		iface := strings.Join(r.EgressIface, ",")
		for _, v := range r.NotEgressIface {
			if iface != "" {
				iface += ","
			}
			iface += "!" + v
		}
		iface = appendSetStrings(iface, egressIfaceSets)
		iface = appendNotSetStrings(iface, notEgressIfaceSets)
		base += " egress_iface=" + iface
	}
	return base
}

// matchAllNamedSets returns true when every set in sets matches the packet
// value corresponding to the set's type.
func matchAllNamedSets(sets []set.Set, ip any, port any, ipPort any, iface any) bool {
	for _, s := range sets {
		if !matchNamedSetByType(s, ip, port, ipPort, iface) {
			return false
		}
	}
	return true
}

// matchAnyNamedSet returns true when any set in sets matches the packet value
// corresponding to the set's type.
func matchAnyNamedSet(sets []set.Set, ip any, port any, ipPort any, iface any) bool {
	for _, s := range sets {
		if matchNamedSetByType(s, ip, port, ipPort, iface) {
			return true
		}
	}
	return false
}

func matchNamedSetByType(s set.Set, ip any, port any, ipPort any, iface any) bool {
	switch s.Type() {
	case set.TypeIP:
		return s.Match(ip)
	case set.TypePort:
		return s.Match(port)
	case set.TypeIPPort:
		return s.Match(ipPort)
	case set.TypeIface:
		return s.Match(iface)
	default:
		return false
	}
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
	if base == "*" || base == "" {
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
	if base == "*" || base == "" {
		return neg
	}
	return base + "," + neg
}

func appendSetStrings(base string, sets []set.Set) string {
	for _, s := range sets {
		base = appendSetString(base, s)
	}
	return base
}

func appendNotSetStrings(base string, sets []set.Set) string {
	for _, s := range sets {
		base = appendNotSetString(base, s)
	}
	return base
}

func filterEndpointSetsByType(sets []set.Set, t set.Type) []set.Set {
	filtered := make([]set.Set, 0, len(sets))
	for _, s := range sets {
		if s.Type() == t {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("CIDR %s is invalid", cidr))
	}
	return ipnet
}

// containsString reports whether slice contains s.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
