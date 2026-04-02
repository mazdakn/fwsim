package engine

import (
	"fmt"

	"github.com/mazdakn/fwsim/internal/match"
	"github.com/mazdakn/fwsim/internal/rule"
	"github.com/mazdakn/fwsim/internal/table"
	"github.com/mazdakn/fwsim/pkg/config"
)

type Config struct {
	// Rule input
	RulesFile string

	// Packet input
	PacketsFile string
}

type Engine struct {
	Config Config

	table   *table.Table
	matches []*match.Match
}

func New(conf Config) *Engine {
	return &Engine{
		Config: conf,
	}
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
	e.table = table.New("main", rule.MustParseAction(rc.DefaultAction))
	for _, r := range rc.Rules {
		e.table.AddRule(r.ToRule())
	}
	return nil
}

func (e *Engine) ConfigPacketsFromFile() error {
	file := e.Config.PacketsFile
	pkts, err := config.PacketsFromFile(e.Config.PacketsFile)
	if err != nil {
		return fmt.Errorf("failed to read packets from %s: %w", file, err)
	}
	e.matches = make([]*match.Match, 0, len(pkts))
	for _, p := range pkts {
		e.matches = append(e.matches, &match.Match{
			Packet: p,
		})
	}
	return nil
}

func (e *Engine) RunTest(m *match.Match) {
	e.table.Match(m)
}

func (e *Engine) RunTests() []*match.Match {
	for _, m := range e.matches {
		e.table.Match(m)
	}
	return e.matches
}
