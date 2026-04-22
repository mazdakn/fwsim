package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Table struct {
	Name          string      `yaml:"name,omitempty"`
	Order         uint64      `yaml:"order,omitempty"`
	DefaultAction string      `yaml:"default_action,omitempty" validate:"isValidAction"`
	Rules         []TableRule `yaml:"rules,omitempty"`
}

func (t *Table) Validate() error {
	return validator.ValidateStructFields(t)
}

func (t *Table) ToTable(sets map[string]set.Set) (*table.Table, error) {
	action, err := rule.ParseAction(t.DefaultAction)
	if err != nil {
		return nil, fmt.Errorf("invalid default_action %q: %w", t.DefaultAction, err)
	}

	tbl := table.New(t.Name, t.Order, action)
	for _, r := range t.Rules {
		mRule, err := r.ToRule(sets)
		if err != nil {
			return nil, err
		}
		tbl.AddRule(mRule)
	}
	return tbl, nil
}

func TableFromBytes(data []byte) (*Table, error) {
	var cfg Table
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func TableFromFile(file string) (*Table, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return TableFromBytes(data)
}
