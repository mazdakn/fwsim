package config

import (
	"fmt"

	"github.com/mazdakn/fwsim/pkg/engine"
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

func ConfigFromFile(conf Config) (engine.Resources, error) {
	if conf.RulesFile == "" {
		return engine.Resources{}, fmt.Errorf("rules file is required")
	}

	resources := engine.Resources{
		Sets: map[string]set.Set{},
	}

	if conf.SetsFile != "" {
		sets, err := ConfigSetsFromFile(conf.SetsFile)
		if err != nil {
			return engine.Resources{}, err
		}
		resources.Sets = sets
	}

	tbl, err := ConfigRulesFromFile(conf.RulesFile, resources.Sets)
	if err != nil {
		return engine.Resources{}, err
	}
	resources.Table = tbl

	if conf.PacketsFile != "" {
		pkts, err := ConfigPacketsFromFile(conf.PacketsFile)
		if err != nil {
			return engine.Resources{}, err
		}
		resources.Packets = pkts
	}

	return resources, nil
}

func ConfigRulesFromBytes(data []byte, sets map[string]set.Set) (*table.Table, error) {
	rc, err := RuleConfigFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules: %w", err)
	}
	tbl, err := toTable(rc, sets)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}
	return tbl, nil
}

func ConfigRulesFromFile(file string, sets map[string]set.Set) (*table.Table, error) {
	rc, err := RuleConfigFromFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules from %s: %w", file, err)
	}
	tbl, err := toTable(rc, sets)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules from %s: %w", file, err)
	}
	return tbl, nil
}

func ConfigPacketsFromBytes(data []byte) ([]*packet.Packet, error) {
	pkts, err := PacketsFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse packets: %w", err)
	}
	return pkts, nil
}

func ConfigPacketsFromFile(file string) ([]*packet.Packet, error) {
	pkts, err := PacketsFromFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read packets from %s: %w", file, err)
	}
	return pkts, nil
}

func ConfigSetsFromBytes(data []byte) (map[string]set.Set, error) {
	sets, err := SetsFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sets: %w", err)
	}
	return sets, nil
}

func ConfigSetsFromFile(file string) (map[string]set.Set, error) {
	sets, err := SetsFromFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read sets from %s: %w", file, err)
	}
	return sets, nil
}

func toTable(rc *RuleConfig, sets map[string]set.Set) (*table.Table, error) {
	if sets == nil {
		sets = map[string]set.Set{}
	}

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
