package engine

import (
	"fmt"

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

func (e *Engine) ConfigFromFile(file string) error {
	rc, err := config.RuleConfigFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to read rules from %s: %w", file, err)
	}
	e.RuleConfig = rc
	for _, r := range e.RuleConfig.Rules {
		e.table.AddRule(r.ToRule())
	}
	e.table.DefaultAction.Action = rule.MustParseAction(e.RuleConfig.DefaultAction)
	return nil
}

func (e *Engine) PacketsFromFile(file string) ([]*packet.Packet, error) {
	pkts, err := config.PacketsFromFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read packets from %s: %w", file, err)
	}
	return pkts, nil
}
