package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Resource struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
	Spec any    `yaml:"spec"`
}

type ResourceFile struct {
	Resources []Resource `yaml:"resources"`
}

// ConfigFromDir reads all YAML files in a directory and loads resources
// (rules, sets, packets) from them.
func ConfigFromDir(dir string) (engine.Resources, error) {
	if strings.TrimSpace(dir) == "" {
		return engine.Resources{}, fmt.Errorf("input directory (--dir) is required")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return engine.Resources{}, fmt.Errorf("failed to read input directory %s: %w", dir, err)
	}

	fileNames := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		fileNames = append(fileNames, e.Name())
	}
	sort.Strings(fileNames)

	var allResources []Resource
	for _, fileName := range fileNames {
		path := filepath.Join(dir, fileName)
		data, err := os.ReadFile(path)
		if err != nil {
			return engine.Resources{}, fmt.Errorf("failed to read resource file %s: %w", path, err)
		}

		fileResources, err := resourcesFromBytes(data)
		if err != nil {
			return engine.Resources{}, fmt.Errorf("failed to parse resource file %s: %w", path, err)
		}
		allResources = append(allResources, fileResources...)
	}

	resources := engine.Resources{
		Sets: map[string]set.Set{},
	}

	ruleConfigs := make([]Rule, 0)
	pkts := make([]*packet.Packet, 0)

	for i, r := range allResources {
		if err := r.validate(i); err != nil {
			return engine.Resources{}, err
		}

		switch r.Type {
		case "set":
			s, err := parseSetResource(r)
			if err != nil {
				return engine.Resources{}, err
			}
			resources.Sets[r.Name] = s
		case "rule":
			rc, err := parseRuleResource(r)
			if err != nil {
				return engine.Resources{}, err
			}
			ruleConfigs = append(ruleConfigs, *rc)
		case "packet":
			p, err := parsePacketResource(r)
			if err != nil {
				return engine.Resources{}, err
			}
			pkts = append(pkts, p.ToPacket())
		}
	}

	tbl := table.New(mainTableName, rule.Drop)
	for _, rc := range ruleConfigs {
		mRule, err := rc.ToRule(resources.Sets)
		if err != nil {
			return engine.Resources{}, fmt.Errorf("failed to load rule %q: %w", rc.Name, err)
		}
		tbl.AddRule(mRule)
	}

	resources.Table = tbl
	resources.Packets = pkts
	return resources, nil
}

func (r Resource) validate(index int) error {
	if strings.TrimSpace(r.Type) == "" {
		return fmt.Errorf("resource[%d]: type is required", index)
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("resource[%d]: name is required", index)
	}
	if r.Spec == nil {
		return fmt.Errorf("resource[%d]: spec is required", index)
	}
	switch r.Type {
	case "packet", "rule", "set":
		return nil
	default:
		return fmt.Errorf("resource[%d]: unsupported type %q", index, r.Type)
	}
}

func resourcesFromBytes(data []byte) ([]Resource, error) {
	var rf ResourceFile
	if err := yaml.Unmarshal(data, &rf); err == nil && len(rf.Resources) > 0 {
		return rf.Resources, nil
	}

	var rs []Resource
	if err := yaml.Unmarshal(data, &rs); err == nil && len(rs) > 0 {
		return rs, nil
	}

	var r Resource
	if err := yaml.Unmarshal(data, &r); err == nil && (r.Type != "" || r.Name != "" || r.Spec != nil) {
		return []Resource{r}, nil
	}

	return nil, fmt.Errorf("no resources found")
}

func parseSetResource(r Resource) (set.Set, error) {
	var s Set
	if err := unmarshalSpec(r.Spec, &s); err != nil {
		return nil, fmt.Errorf("set %q: %w", r.Name, err)
	}
	s.Name = r.Name

	namedSet, err := s.ToSet()
	if err != nil {
		return nil, err
	}
	return namedSet, nil
}

func parseRuleResource(r Resource) (*Rule, error) {
	var rc Rule
	if err := unmarshalSpec(r.Spec, &rc); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.Name, err)
	}
	rc.Name = r.Name
	if err := validator.ValidateStructFields(&rc); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.Name, err)
	}
	return &rc, nil
}

func parsePacketResource(r Resource) (*Packet, error) {
	var p Packet
	if err := unmarshalSpec(r.Spec, &p); err != nil {
		return nil, fmt.Errorf("packet %q: %w", r.Name, err)
	}
	p.Metadata.Name = r.Name
	if err := validator.ValidateStructFields(&p); err != nil {
		return nil, fmt.Errorf("packet %q: %w", r.Name, err)
	}
	return &p, nil
}

func unmarshalSpec(spec any, out any) error {
	data, err := yaml.Marshal(spec)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return err
	}
	return nil
}
