package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Config struct {
	// Base directory input. Expects tables/, sets/, packets/ sub-directories.
	InputDir string

	// LoadPackets controls whether packets/ input is loaded.
	LoadPackets bool

	// LoadIntents controls whether intents/ input is loaded.
	LoadIntents bool
}

func ConfigFromFile(conf Config) (engine.Resources, error) {
	if conf.InputDir == "" {
		return engine.Resources{}, fmt.Errorf("input directory is required")
	}
	return ConfigFromDirectory(conf)
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

	tables, err := ConfigTablesFromDir(filepath.Join(conf.InputDir, "tables"), resources.Sets)
	if err != nil {
		return engine.Resources{}, err
	}
	resources.Tables = tables

	if conf.LoadPackets {
		pkts, err := ConfigPacketsFromDir(filepath.Join(conf.InputDir, "packets"))
		if err != nil {
			return engine.Resources{}, err
		}
		resources.Packets = pkts
	}

	if conf.LoadIntents {
		intents, err := ConfigIntentsFromDir(filepath.Join(conf.InputDir, "intents"))
		if err != nil {
			return engine.Resources{}, err
		}
		resources.Intents = intents
	}

	return resources, nil
}

func ConfigTableFromBytes(data []byte, sets map[string]set.Set) (*table.Table, error) {
	t, err := TableFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse table: %w", err)
	}
	tbl, err := toTable(t, sets)
	if err != nil {
		return nil, fmt.Errorf("failed to load table: %w", err)
	}
	return tbl, nil
}

func ConfigTableFromFile(file string, sets map[string]set.Set) (*table.Table, error) {
	t, err := TableFromFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read table from %s: %w", file, err)
	}
	tbl, err := toTable(t, sets)
	if err != nil {
		return nil, fmt.Errorf("failed to load table from %s: %w", file, err)
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
	tables, err := ConfigTablesFromDir(dir, sets)
	if err != nil {
		return nil, err
	}
	if len(tables) == 0 {
		return nil, nil
	}
	return tables[0], nil
}

func ConfigTablesFromDir(dir string, sets map[string]set.Set) ([]*table.Table, error) {
	files, err := yamlFilesInDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*table.Table{}, nil
		}
		return nil, fmt.Errorf("failed to read tables directory %s: %w", dir, err)
	}
	if len(files) == 0 {
		return []*table.Table{}, nil
	}

	tables := make([]*table.Table, 0, len(files))
	for _, file := range files {
		tbl, err := ConfigTableFromFile(file, sets)
		if err != nil {
			return nil, err
		}
		tables = append(tables, tbl)
	}
	table.SortTables(tables)
	return tables, nil
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

func ConfigIntentsFromDir(dir string) ([]*match.MatchContext, error) {
	files, err := yamlFilesInDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read intents directory %s: %w", dir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no yaml files found in intents directory %s", dir)
	}
	var contexts []*match.MatchContext
	for _, file := range files {
		intent, err := IntentFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read intent from %s: %w", file, err)
		}
		mc, err := intent.ToMatchContext()
		if err != nil {
			return nil, fmt.Errorf("failed to convert intent in %s: %w", file, err)
		}
		contexts = append(contexts, mc)
	}
	return contexts, nil
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

func toTable(t *Table, sets map[string]set.Set) (*table.Table, error) {
	if sets == nil {
		sets = map[string]set.Set{}
	}

	tbl := table.New(t.Name, t.Order, rule.MustParseAction(t.DefaultAction))
	for _, r := range t.Rules {
		mRule, err := r.ToRule(sets)
		if err != nil {
			return nil, err
		}
		tbl.AddRule(mRule)
	}
	return tbl, nil
}
