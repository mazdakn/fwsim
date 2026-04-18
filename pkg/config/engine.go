package config

import (
	"fmt"

	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/table"
)

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
	tbl := table.New("main", rule.MustParseAction(rc.DefaultAction))
	for _, r := range rc.Rules {
		mRule, err := r.ToRule(e.Sets())
		if err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
		tbl.AddRule(mRule)
	}
	e.SetTable(tbl)
	return nil
}

func ConfigRulesFromFile(e *engine.Engine, file string) error {
	rc, err := RuleConfigFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to read rules from %s: %w", file, err)
	}
	tbl := table.New("main", rule.MustParseAction(rc.DefaultAction))
	for _, r := range rc.Rules {
		mRule, err := r.ToRule(e.Sets())
		if err != nil {
			return fmt.Errorf("failed to load rules from %s: %w", file, err)
		}
		tbl.AddRule(mRule)
	}
	e.SetTable(tbl)
	return nil
}

func ConfigPacketsFromBytes(e *engine.Engine, data []byte) error {
	pkts, err := PacketsFromBytes(data)
	if err != nil {
		return fmt.Errorf("failed to parse packets: %w", err)
	}
	matches := make([]*match.Match, 0, len(pkts))
	for _, p := range pkts {
		matches = append(matches, &match.Match{
			Packet: p,
		})
	}
	e.SetMatches(matches)
	return nil
}

func ConfigPacketsFromFile(e *engine.Engine, file string) error {
	pkts, err := PacketsFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to read packets from %s: %w", file, err)
	}
	matches := make([]*match.Match, 0, len(pkts))
	for _, p := range pkts {
		matches = append(matches, &match.Match{
			Packet: p,
		})
	}
	e.SetMatches(matches)
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
