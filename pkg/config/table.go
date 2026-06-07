package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/conntrack"
	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type Table struct {
	Name          string  `yaml:"name"                   validate:"isNonEmpty"`
	Order         uint64  `yaml:"order,omitempty"`
	Chains        []Chain `yaml:"chains,omitempty"`
	DefaultAction string  `yaml:"default_action,omitempty" validate:"isValidAction"`
}

func (t *Table) Validate() error {
	if err := validator.ValidateStructFields(t); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, c := range t.Chains {
		if seen[c.Name] {
			return fmt.Errorf("table %q has duplicate chain name %q", t.Name, c.Name)
		}
		seen[c.Name] = true
	}
	return nil
}

// Chain represents the YAML configuration structure for a chain.
type Chain struct {
	Name  string `yaml:"name" validate:"isNonEmpty"`
	Rules []Rule `yaml:"rules,omitempty"`
}

// Endpoint groups the network, port, and interface match criteria for one traffic direction
// in the YAML configuration.
type Endpoint struct {
	Net   []string    `yaml:"net,omitempty"        validate:"isValidCIDR"`
	Port  []port.Port `yaml:"port,omitempty"       validate:"isPortValid"`
	Iface []string    `yaml:"iface,omitempty"`
	Sets  []string    `yaml:"sets,omitempty"`
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

	if len(e.Iface) > 0 {
		ep.Iface = set.NewIfaceSet()
		for _, iface := range e.Iface {
			if err := ep.Iface.Add(iface); err != nil {
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
	Protocol       []proto.Proto `yaml:"proto,omitempty"          validate:"isProtoValid"`
	ConnState      []string      `yaml:"ct_state,omitempty"       validate:"isValidConnState"`
	NotSource      Endpoint      `yaml:"not_src,omitempty"`
	NotDestination Endpoint      `yaml:"not_dst,omitempty"`
	NotProto       []proto.Proto `yaml:"not_proto,omitempty"      validate:"isProtoValid"`
	NotConnState   []string      `yaml:"not_ct_state,omitempty"   validate:"isValidConnState"`
	Action         string        `yaml:"action,omitempty"         validate:"isValidAction"`
	JumpTarget     string        `yaml:"jump_target,omitempty"`
}

// ToRule converts a Rule config into a Rule domain object.
// sets is the map of pre-loaded named sets; any set name referenced by this
// rule that is not present in sets causes an error.
func (r *Rule) ToRule(sets map[string]set.Set) (*rule.Rule, error) {
	mRule := rule.New()
	mRule.Name = r.Name
	mRule.Order = r.Order
	mRule.Action = rule.MustParseAction(r.Action)
	mRule.JumpTarget = r.JumpTarget

	if mRule.Action == rule.Jump && mRule.JumpTarget == "" {
		return nil, fmt.Errorf("rule %q has jump action but no jump_target", r.Name)
	}

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

	for _, rawState := range r.ConnState {
		state, err := conntrack.ParseState(rawState)
		if err != nil {
			return nil, err
		}
		mRule.ConnState = append(mRule.ConnState, state)
	}

	for _, rawState := range r.NotConnState {
		state, err := conntrack.ParseState(rawState)
		if err != nil {
			return nil, err
		}
		mRule.NotConnState = append(mRule.NotConnState, state)
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
	var t Table
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

func TableFromFile(file string) (*Table, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return TableFromBytes(data)
}
