package set

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mazdakn/fwsim/pkg/port"
)

// PortSet is a set of uint16 port values.
type PortSet struct {
	set[uint16]
}

// NewPortSet returns an empty PortSet.
func NewPortSet() *PortSet {
	return &PortSet{*New[uint16]()}
}

// Add inserts a value into the set. v must be a uint16 port number, a port.Port,
// or a string representation of a port number or well-known port name (e.g.
// "http"). It implements the Set interface.
func (p *PortSet) Add(v any) error {
	switch val := v.(type) {
	case uint16:
		p.set.Add(val)
		return nil
	case port.Port:
		p.set.Add(val.Resolve())
		return nil
	case string:
		parsed, err := port.Parse(val)
		if err != nil {
			return fmt.Errorf("invalid port %q: %w", val, err)
		}
		p.set.Add(parsed.Number)
		return nil
	default:
		return fmt.Errorf("PortSet.Add: unsupported type %T", v)
	}
}

// Match reports whether v is present in the set. v must be a uint16 port
// number. It implements the Set interface.
func (p *PortSet) Match(v any) bool {
	port, ok := v.(uint16)
	if !ok {
		return false
	}
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
