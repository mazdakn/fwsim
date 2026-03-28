package set

import (
	"sort"
	"strconv"
	"strings"
)

// PortSet is a Set of uint16 port values.
type PortSet struct {
	Set[uint16]
	Negated bool
}

// NewPortSet returns an empty PortSet.
func NewPortSet() *PortSet {
	return &PortSet{Set: *New[uint16]()}
}

// Match reports whether port is present in the set.
// If Negated is true, it returns true when port is NOT in the set.
func (p *PortSet) Match(port uint16) bool {
	result := p.Exists(port)
	if p.Negated {
		return !result
	}
	return result
}

// String returns a human-readable representation of the PortSet.
// A single-port set renders as its number (e.g. "80").
// A multi-port set renders as a sorted brace-enclosed list (e.g. "{80,443}").
// A negated set is prefixed with "!" (e.g. "!80").
func (p *PortSet) String() string {
	ports := make([]uint16, 0, len(p.items))
	for port := range p.items {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	prefix := ""
	if p.Negated {
		prefix = "!"
	}
	if len(ports) == 1 {
		return prefix + strconv.Itoa(int(ports[0]))
	}
	var sb strings.Builder
	sb.WriteString(prefix)
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
