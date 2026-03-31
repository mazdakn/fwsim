package engine

import (
	"github.com/mazdakn/fwsim/internal/packet"
	"github.com/mazdakn/fwsim/internal/rule"
	"github.com/mazdakn/fwsim/internal/table"
	"github.com/mazdakn/fwsim/pkg/config"
)

type Engine struct {
	ruleConfig *config.Config

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

func (e *Engine) ConfigFromFile(file string) error {
	rc, err := config.ConfigFromFile(file)
	if err != nil {
		return err
	}
	e.ruleConfig = rc
	return nil
}

func (e *Engine) LoadRules() error {
	for _, r := range e.ruleConfig.Rules {
		loaded, err := r.ToRule()
		if err != nil {
			return err
		}
		e.table.AddRule(loaded)
	}
	e.table.DefaultAction.Action = rule.MustParseAction(e.ruleConfig.DefaultAction)
	return nil
}

func (e *Engine) PacketsFromFile(file string) ([]*packet.Packet, error) {
	return config.PacketsFromFile(file)
}
