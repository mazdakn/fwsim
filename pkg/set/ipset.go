package set

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/mazdakn/fwsim/pkg/packet"
)

// IPSet is a Set of net.IPNet CIDR blocks.
type IPSet struct {
	nets map[string]*net.IPNet
}

// NewIPSet returns an empty IPSet.
func NewIPSet() *IPSet {
	return &IPSet{
		nets: make(map[string]*net.IPNet),
	}
}

// Add parses cidr and inserts the resulting network into the set.
// It implements the Set interface.
func (s *IPSet) Add(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	s.AddNet(ipnet)
	return nil
}

// AddNet inserts ipnet into the set.
func (s *IPSet) AddNet(ipnet *net.IPNet) {
	s.nets[ipnet.String()] = ipnet
}

// DeleteNet removes ipnet from the set.
func (s *IPSet) DeleteNet(ipnet *net.IPNet) {
	delete(s.nets, ipnet.String())
}

// Match reports whether either the source or destination address of pkt is
// contained in any network in the set.
// It implements the Set interface.
func (s *IPSet) Match(pkt *packet.Packet) bool {
	return s.MatchIP(pkt.SrcAddr) || s.MatchIP(pkt.DstAddr)
}

// MatchIP reports whether ip is contained in any of the networks in the set.
func (s *IPSet) MatchIP(ip net.IP) bool {
	for _, ipnet := range s.nets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// String returns a human-readable representation of the IPSet.
// A single-network set renders as its CIDR (e.g. "10.0.0.0/8").
// A multi-network set renders as a sorted brace-enclosed list (e.g. "{10.0.0.0/8,192.168.0.0/16}").
func (s *IPSet) String() string {
	cidrs := make([]string, 0, len(s.nets))
	for cidr := range s.nets {
		cidrs = append(cidrs, cidr)
	}
	sort.Strings(cidrs)
	if len(cidrs) == 1 {
		return cidrs[0]
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, cidr := range cidrs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(cidr)
	}
	sb.WriteByte('}')
	return sb.String()
}
