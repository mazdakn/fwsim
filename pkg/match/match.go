package match

import (
	"fmt"

	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
)

type Verdict int

const Undefined Verdict = -1

const (
	Accept Verdict = iota
	Drop
	Pass
	NoMatch
)

func (v Verdict) String() string {
	switch v {
	case Accept:
		return "Accept"
	case Drop:
		return "Drop"
	case Pass:
		return "Pass"
	case NoMatch:
		return "no match"
	default:
		return fmt.Sprintf("Undefined(%d)", v)
	}
}

func VerdictFromAction(a rule.Action) Verdict {
	switch a {
	case rule.Accept:
		return Accept
	case rule.Drop:
		return Drop
	case rule.Pass:
		return Pass
	default:
		return Undefined
	}
}

type MatchContext struct {
	Packet  *packet.Packet
	Verdict Verdict
	Trace   []*rule.Rule
}

func New() *MatchContext {
	return &MatchContext{
		Verdict: NoMatch,
	}
}

func NewWithPacket(pkt *packet.Packet) *MatchContext {
	m := New()
	m.Packet = pkt
	return m
}
