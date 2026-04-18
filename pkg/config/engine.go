package config

import (
	"fmt"

	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

const mainTableName = "main"

type Config struct {
	// Rule input
	RulesFile string

	// Packet input
	PacketsFile string

	// Sets input
	SetsFile string
}

func ConfigFromFile(e *engine.Engine, conf Config) error {
	if conf.SetsFile != "" {
		if err := ConfigSetsFromFile(e, conf.SetsFile); err != nil {
			return err
		}
	}
	if err := ConfigRulesFromFile(e, conf.RulesFile); err != nil {
		return err
	}
	if err := ConfigPacketsFromFile(e, conf.PacketsFile); err != nil {
		return err
	}
	return nil
}

func ConfigRulesFromBytes(e *engine.Engine, data []byte) error {
	rc, err := RuleConfigFromBytes(data)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}
	tbl, err := toTable(rc, e.Sets())
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}
	e.SetTable(tbl)
	return nil
}

func ConfigRulesFromFile(e *engine.Engine, file string) error {
	rc, err := RuleConfigFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to read rules from %s: %w", file, err)
	}
	tbl, err := toTable(rc, e.Sets())
	if err != nil {
		return fmt.Errorf("failed to load rules from %s: %w", file, err)
	}
	e.SetTable(tbl)
	return nil
}

func ConfigPacketsFromBytes(e *engine.Engine, data []byte) error {
	pkts, err := PacketsFromBytes(data)
	if err != nil {
		return fmt.Errorf("failed to parse packets: %w", err)
	}
	e.SetMatches(toMatches(pkts))
	return nil
}

func ConfigPacketsFromFile(e *engine.Engine, file string) error {
	pkts, err := PacketsFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to read packets from %s: %w", file, err)
	}
	e.SetMatches(toMatches(pkts))
	return nil
}

func ConfigSetsFromBytes(e *engine.Engine, data []byte) error {
	sets, err := SetsFromBytes(data)
	if err != nil {
		return fmt.Errorf("failed to parse sets: %w", err)
	}
	e.SetSets(sets)
	return nil
}

func ConfigSetsFromFile(e *engine.Engine, file string) error {
	sets, err := SetsFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to read sets from %s: %w", file, err)
	}
	e.SetSets(sets)
	return nil
}

func toTable(rc *RuleConfig, sets map[string]set.Set) (*table.Table, error) {
	tbl := table.New(mainTableName, rule.MustParseAction(rc.DefaultAction))
	for _, r := range rc.Rules {
		mRule, err := r.ToRule(sets)
		if err != nil {
			return nil, err
		}
		tbl.AddRule(mRule)
	}
	return tbl, nil
}

func toMatches(pkts []*packet.Packet) []*match.Match {
	matches := make([]*match.Match, 0, len(pkts))
	for _, p := range pkts {
		matches = append(matches, &match.Match{
			Packet: p,
		})
	}
	return matches
}
