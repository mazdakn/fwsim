package set

import (
	"sort"
	"strings"

	"github.com/mazdakn/fwsim/pkg/proto"
)

// ProtoSet is a Set of Proto protocol values.
type ProtoSet struct {
	Set[proto.Proto]
}

// NewProtoSet returns an empty ProtoSet.
func NewProtoSet() *ProtoSet {
	return &ProtoSet{*New[proto.Proto]()}
}

// Match reports whether p is present in the set.
func (ps *ProtoSet) Match(p proto.Proto) bool {
	return ps.Exists(p)
}

// String returns a human-readable representation of the ProtoSet.
// A single-protocol set renders as its name or number (e.g. "tcp").
// A multi-protocol set renders as a sorted brace-enclosed list (e.g. "{tcp,udp}").
func (ps *ProtoSet) String() string {
	protos := make([]proto.Proto, 0, len(ps.items))
	for p := range ps.items {
		protos = append(protos, p)
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i] < protos[j] })
	if len(protos) == 1 {
		return protos[0].String()
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, p := range protos {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(p.String())
	}
	sb.WriteByte('}')
	return sb.String()
}
