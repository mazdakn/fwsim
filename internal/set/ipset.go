package set

import (
	"net"
	"sort"
	"strings"
)

// IPSet is a Set of net.IPNet CIDR blocks.
type IPSet struct {
	nets map[string]*net.IPNet
}

// NewIPSet returns an empty IPSet.
func NewIPSet() *IPSet {
	return &IPSet{nets: make(map[string]*net.IPNet)}
}

// Add inserts ipnet into the set.
func (s *IPSet) Add(ipnet *net.IPNet) {
	if ipnet == nil {
		return
	}
	s.nets[ipnet.String()] = ipnet
}

// Delete removes ipnet from the set.
func (s *IPSet) Delete(ipnet *net.IPNet) {
	if ipnet == nil {
		return
	}
	delete(s.nets, ipnet.String())
}

// Match reports whether ip is contained in any of the networks in the set.
func (s *IPSet) Match(ip net.IP) bool {
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
