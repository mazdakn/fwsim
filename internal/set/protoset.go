package set

import (
	"sort"
	"strconv"
	"strings"
)

// ProtoSet is a Set of uint16 protocol values.
type ProtoSet struct {
	Set[uint16]
}

// NewProtoSet returns an empty ProtoSet.
func NewProtoSet() *ProtoSet {
	return &ProtoSet{*New[uint16]()}
}

// Match reports whether proto is present in the set.
func (p *ProtoSet) Match(proto uint16) bool {
	return p.Exists(proto)
}

// String returns a human-readable representation of the ProtoSet.
// A single-protocol set renders as its number (e.g. "6").
// A multi-protocol set renders as a sorted brace-enclosed list (e.g. "{6,17}").
func (p *ProtoSet) String() string {
	protos := make([]uint16, 0, len(p.items))
	for proto := range p.items {
		protos = append(protos, proto)
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i] < protos[j] })
	if len(protos) == 1 {
		return strconv.Itoa(int(protos[0]))
	}
	var sb strings.Builder
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
