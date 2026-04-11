package set

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mazdakn/fwsim/pkg/packet"
)

// PortSet is a set of uint16 port values.
type PortSet struct {
	set[uint16]
}

// NewPortSet returns an empty PortSet.
func NewPortSet() *PortSet {
	return &PortSet{*New[uint16]()}
}

// Add parses s as a port number and inserts it into the set.
// It implements the Set interface.
func (p *PortSet) Add(s string) error {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", s, err)
	}
	p.AddPort(uint16(n))
	return nil
}

// AddPort inserts port into the set.
func (p *PortSet) AddPort(port uint16) {
	p.set.Add(port)
}

// Match reports whether either the source or destination port of pkt is
// present in the set. This OR semantics is intentional for standalone named
// sets: when a set is used outside a specific rule field context, it matches
// if either port of the packet is in the set.
// It implements the Set interface.
func (p *PortSet) Match(pkt *packet.Packet) bool {
	return p.MatchPort(pkt.SrcPort) || p.MatchPort(pkt.DstPort)
}

// MatchPort reports whether port is present in the set.
func (p *PortSet) MatchPort(port uint16) bool {
	return p.Exists(port)
}

// String returns a human-readable representation of the PortSet.
// A single-port set renders as its number (e.g. "80").
// A multi-port set renders as a sorted brace-enclosed list (e.g. "{80,443}").
func (p *PortSet) String() string {
	ports := make([]uint16, 0, len(p.items))
	for port := range p.items {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	if len(ports) == 1 {
		return strconv.Itoa(int(ports[0]))
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, port := range ports {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(int(port)))
	}
	sb.WriteByte('}')
	return sb.String()
}
