package engine

import (
	"fmt"

	"github.com/mazdakn/fwsim/internal/packet"
	"github.com/mazdakn/fwsim/internal/rule"
	"github.com/mazdakn/fwsim/internal/table"
	"github.com/mazdakn/fwsim/pkg/config"
)

type Config struct {
	// Rule input
	RulesFile string

	// Packet input
	PacketsFile string
	Packet      *config.Packet
}

type Engine struct {
	Config     Config
	RuleConfig *config.RuleConfig

	table   *table.Table
	packets []*packet.Packet
}

func New(conf Config) *Engine {
	return &Engine{
		Config: conf,
		table:  table.New("main", rule.Drop),
	}
}

func (e *Engine) Match(pkt *packet.Packet) table.Result {
	return e.table.Match(pkt)
}

func (e *Engine) ConfigFromFile() error {
	if err := e.ConfigRulesFromFile(); err != nil {
		return err
	}
	if err := e.ConfigPacketsFromFile(); err != nil {
		return err
	}
	return nil
}

func (e *Engine) ConfigRulesFromFile() error {
	file := e.Config.RulesFile
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

func (e *Engine) ConfigPacketsFromFile() error {
	file := e.Config.PacketsFile
	pkts, err := config.PacketsFromFile(e.Config.PacketsFile)
	if err != nil {
		return fmt.Errorf("failed to read packets from %s: %w", file, err)
	}
	e.packets = pkts
	return nil
}
