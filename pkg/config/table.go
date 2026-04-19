package config

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/table"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Table struct {
	Name          string `yaml:"name,omitempty"`
	Order         uint64 `yaml:"order,omitempty"`
	DefaultAction string `yaml:"default_action,omitempty" validate:"isValidAction"`
}

func (t *Table) Validate() error {
	return validator.ValidateStructFields(t)
}

func (t *Table) ToTable() (*table.Table, error) {
	action, err := rule.ParseAction(t.DefaultAction)
	if err != nil {
		return nil, err
	}
	return table.New(t.Name, t.Order, action), nil
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
