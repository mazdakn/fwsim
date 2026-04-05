package types

import (
	"sort"
	"strconv"
	"strings"
)

// PortSet is a Set of uint16 port values.
type PortSet struct {
	Set[uint16]
}

// NewPortSet returns an empty PortSet.
func NewPortSet() *PortSet {
	return &PortSet{*New[uint16]()}
}

// Match reports whether port is present in the set.
func (p *PortSet) Match(port uint16) bool {
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
