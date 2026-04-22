package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Table struct {
	Name          string `yaml:"name"`
	Rules         []Rule `yaml:"rules,omitempty"`
	DefaultAction string `yaml:"default_action,omitempty" validate:"isValidAction"`
}

func (rc *Table) Validate() error {
	if err := validator.ValidateStructFields(rc); err != nil {
		return err
	}
	if rc.Name == "" {
		return fmt.Errorf("name is required")
	}
	if _, err := rule.ParseAction(rc.DefaultAction); err != nil {
		return err
	}
	return nil
}

// Endpoint groups the network and port match criteria for one traffic direction
// in the YAML configuration.
type Endpoint struct {
	Net  []string    `yaml:"net,omitempty"        validate:"isValidCIDR"`
	Port []port.Port `yaml:"port,omitempty"       validate:"isPortValid"`
	Sets []string    `yaml:"sets,omitempty"`
}

// toEndpoint converts an Endpoint config into a rule.Endpoint domain object.
// sets is the map of pre-loaded named sets; any set name referenced that is
// not present in sets causes an error.
func (e *Endpoint) toEndpoint(ruleName string, sets map[string]set.Set) (rule.Endpoint, error) {
	var ep rule.Endpoint

	if len(e.Net) > 0 {
		ep.Net = set.NewIPSet()
		for _, n := range e.Net {
			if err := ep.Net.Add(rule.MustParseCIDR(n)); err != nil {
				return rule.Endpoint{}, err
			}
		}
	}

	if len(e.Port) > 0 {
		ep.Port = set.NewPortSet()
		for _, p := range e.Port {
			if err := ep.Port.Add(p); err != nil {
				return rule.Endpoint{}, err
			}
		}
	}

	if len(e.Sets) > 0 {
		ep.Sets = make([]set.Set, 0, len(e.Sets))
		for _, setName := range e.Sets {
			s, ok := sets[setName]
			if !ok {
				return ep, fmt.Errorf("rule %q references unknown set %q", ruleName, setName)
			}
			ep.Sets = append(ep.Sets, s)
		}
	}

	return ep, nil
}

// Rule represents the YAML configuration structure for a firewall rule.
type Rule struct {
	Name           string        `yaml:"name,omitempty"`
	Order          uint64        `yaml:"order,omitempty"`
	Source         Endpoint      `yaml:"src,omitempty"`
	Destination    Endpoint      `yaml:"dst,omitempty"`
	Protocol       []proto.Proto `yaml:"proto,omitempty"     validate:"isProtoValid"`
	NotSource      Endpoint      `yaml:"not_src,omitempty"`
	NotDestination Endpoint      `yaml:"not_dst,omitempty"`
	NotProto       []proto.Proto `yaml:"not_proto,omitempty" validate:"isProtoValid"`
	Action         string        `yaml:"action,omitempty"    validate:"isValidAction"`
}

// ToRule converts a Rule config into a Rule domain object.
// sets is the map of pre-loaded named sets; any set name referenced by this
// rule that is not present in sets causes an error.
func (r *Rule) ToRule(sets map[string]set.Set) (*rule.Rule, error) {
	mRule := rule.New()
	mRule.Name = r.Name
	mRule.Order = r.Order
	mRule.Action = rule.MustParseAction(r.Action)

	if len(r.Protocol) > 0 {
		mRule.Proto = set.NewProtoSet()
		for _, proto := range r.Protocol {
			if err := mRule.Proto.Add(proto); err != nil {
				return nil, err
			}
		}
	}

	if len(r.NotProto) > 0 {
		mRule.NotProto = set.NewProtoSet()
		for _, proto := range r.NotProto {
			if err := mRule.NotProto.Add(proto); err != nil {
				return nil, err
			}
		}
	}

	var err error
	mRule.Source, err = r.Source.toEndpoint(r.Name, sets)
	if err != nil {
		return nil, err
	}

	mRule.Destination, err = r.Destination.toEndpoint(r.Name, sets)
	if err != nil {
		return nil, err
	}

	mRule.NotSource, err = r.NotSource.toEndpoint(r.Name, sets)
	if err != nil {
		return nil, err
	}

	mRule.NotDestination, err = r.NotDestination.toEndpoint(r.Name, sets)
	if err != nil {
		return nil, err
	}

	return mRule, nil
}

func TableFromBytes(data []byte) (*Table, error) {
	var rc Table
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return nil, err
	}
	if err := rc.Validate(); err != nil {
		return nil, err
	}
	return &rc, nil
}

func TableFromFile(file string) (*Table, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return TableFromBytes(data)
}
