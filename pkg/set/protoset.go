package set

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/proto"
)

// ProtoSet is a set of Proto protocol values.
type ProtoSet struct {
	set[proto.Proto]
}

// NewProtoSet returns an empty ProtoSet.
func NewProtoSet() *ProtoSet {
	return &ProtoSet{*New[proto.Proto]()}
}

// Add parses s as a protocol name or number and inserts it into the set.
// It implements the Set interface.
func (ps *ProtoSet) Add(s string) error {
	p, err := proto.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid protocol %q: %w", s, err)
	}
	ps.AddProto(*p)
	return nil
}

// AddProto inserts p into the set.
func (ps *ProtoSet) AddProto(p proto.Proto) {
	ps.set.Add(p)
}

// Match reports whether the protocol of pkt is present in the set.
// It implements the Set interface.
func (ps *ProtoSet) Match(pkt *packet.Packet) bool {
	return ps.MatchProto(pkt.Proto)
}

// MatchProto reports whether p is present in the set.
func (ps *ProtoSet) MatchProto(p proto.Proto) bool {
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
