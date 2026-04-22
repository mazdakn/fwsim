package match

import (
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
)

// Result holds the outcome of matching a packet against a Table.
type Result struct {
	Verdict rule.Verdict
	Trace   []*rule.Rule
}

type MatchContext struct {
	Packet *packet.Packet
	Result
}

func New() *MatchContext {
	return &MatchContext{}
}
