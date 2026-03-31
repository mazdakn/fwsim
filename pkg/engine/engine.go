package engine

import (
	"github.com/mazdakn/fwsim/internal/packet"
	"github.com/mazdakn/fwsim/internal/rule"
	"github.com/mazdakn/fwsim/internal/table"
	"github.com/mazdakn/fwsim/pkg/config"
)

type Engine struct {
	RuleConfig *config.RuleConfig

	table *table.Table
}

func New() *Engine {
	return &Engine{
		table: table.New("main", rule.Drop),
	}
}

func (e *Engine) Match(pkt *packet.Packet) table.Result {
	return e.table.Match(pkt)
}

func (e *Engine) LoadConfigs() {
	// TODO: Fix me
	//rules := make([]*rule.Rule, 0, len(rc.Rules))
	for _, r := range e.RuleConfig.Rules {
		e.table.AddRule(r.ToRule())
	}
	e.table.DefaultAction.Action = rule.MustParseAction(e.RuleConfig.DefaultAction)
}
