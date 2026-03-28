package set

import (
	"sort"
	"strconv"
	"strings"
)

// ProtoSet is a Set of uint8 protocol values.
type ProtoSet struct {
	Set[uint8]
	Negated bool
}

// NewProtoSet returns an empty ProtoSet.
func NewProtoSet() *ProtoSet {
	return &ProtoSet{Set: *New[uint8]()}
}

// Match reports whether proto is present in the set.
// If Negated is true, it returns true when proto is NOT in the set.
func (p *ProtoSet) Match(proto uint8) bool {
	result := p.Exists(proto)
	if p.Negated {
		return !result
	}
	return result
}

// String returns a human-readable representation of the ProtoSet.
// A single-protocol set renders as its number (e.g. "6").
// A multi-protocol set renders as a sorted brace-enclosed list (e.g. "{6,17}").
// A negated set is prefixed with "!" (e.g. "!6").
func (p *ProtoSet) String() string {
	protos := make([]uint8, 0, len(p.items))
	for proto := range p.items {
		protos = append(protos, proto)
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i] < protos[j] })
	prefix := ""
	if p.Negated {
		prefix = "!"
	}
	if len(protos) == 1 {
		return prefix + strconv.Itoa(int(protos[0]))
	}
	var sb strings.Builder
	sb.WriteString(prefix)
	sb.WriteByte('{')
	for i, proto := range protos {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(int(proto)))
	}
	sb.WriteByte('}')
	return sb.String()
}
