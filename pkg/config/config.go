package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

const mainTableName = "main"

type Config struct {
	// Base directory input. Expects rules/, sets/, packets/ sub-directories.
	InputDir string

	// Rule input
	RulesFile string

	// Packet input
	PacketsFile string

	// Sets input
	SetsFile string
}

func ConfigFromFile(conf Config) (engine.Resources, error) {
	if conf.InputDir != "" {
		return ConfigFromDirectory(conf)
	}

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

func ConfigFromDirectory(conf Config) (engine.Resources, error) {
	resources := engine.Resources{
		Sets: map[string]set.Set{},
	}

	sets, err := ConfigSetsFromDir(filepath.Join(conf.InputDir, "sets"))
	if err != nil {
		return engine.Resources{}, err
	}
	resources.Sets = sets

	tbl, err := ConfigRulesFromDir(filepath.Join(conf.InputDir, "rules"), resources.Sets)
	if err != nil {
		return engine.Resources{}, err
	}
	resources.Table = tbl

	if conf.PacketsFile != "" {
		pkts, err := ConfigPacketsFromDir(filepath.Join(conf.InputDir, "packets"))
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

func ConfigRulesFromDir(dir string, sets map[string]set.Set) (*table.Table, error) {
	files, err := yamlFilesInDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules directory %s: %w", dir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no yaml files found in rules directory %s", dir)
	}

	merged := &RuleConfig{}
	for _, file := range files {
		rc, err := RuleConfigFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read rules from %s: %w", file, err)
		}
		merged.Rules = append(merged.Rules, rc.Rules...)
		if rc.DefaultAction == "" {
			continue
		}
		if merged.DefaultAction == "" {
			merged.DefaultAction = rc.DefaultAction
			continue
		}
		if merged.DefaultAction != rc.DefaultAction {
			return nil, fmt.Errorf("conflicting default_action in %s: %s (expected %s)", file, rc.DefaultAction, merged.DefaultAction)
		}
	}

	if merged.DefaultAction == "" {
		return nil, fmt.Errorf("no default_action found in any rules file under %s", dir)
	}
	return toTable(merged, sets)
}

func ConfigPacketsFromDir(dir string) ([]*packet.Packet, error) {
	files, err := yamlFilesInDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read packets directory %s: %w", dir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no yaml files found in packets directory %s", dir)
	}
	var pkts []*packet.Packet
	for _, file := range files {
		filePkts, err := ConfigPacketsFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read packets from %s: %w", file, err)
		}
		pkts = append(pkts, filePkts...)
	}
	return pkts, nil
}

func ConfigSetsFromDir(dir string) (map[string]set.Set, error) {
	files, err := yamlFilesInDir(dir)
	if err != nil {
		// Sets are optional; missing directory means no named sets configured.
		if os.IsNotExist(err) {
			return map[string]set.Set{}, nil
		}
		return nil, fmt.Errorf("failed to read sets directory %s: %w", dir, err)
	}
	sets := make(map[string]set.Set)
	for _, file := range files {
		fileSets, err := ConfigSetsFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read sets from %s: %w", file, err)
		}
		for name, v := range fileSets {
			if _, exists := sets[name]; exists {
				return nil, fmt.Errorf("duplicate set %q found in %s", name, file)
			}
			sets[name] = v
		}
	}
	return sets, nil
}

func yamlFilesInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(files)
	return files, nil
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
