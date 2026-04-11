package match

import (
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
)

// Result holds the outcome of matching a packet against a Table.
type Result struct {
	Verdict rule.Action
	Trace   []*rule.Rule
}

type Match struct {
	Packet *packet.Packet
	Result Result
}

func New() *Match {
	return &Match{}
}
