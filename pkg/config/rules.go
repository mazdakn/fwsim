package config

import (
	"fmt"

	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/validator"
)

// Endpoint groups the network and port match criteria for one traffic direction
// in the YAML configuration.
type Endpoint struct {
	Net  []string    `yaml:"net,omitempty"  validate:"isValidCIDR"`
	Port []port.Port `yaml:"port,omitempty" validate:"isPortValid"`
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

// TableRule represents a firewall rule entry nested under a table definition.
type TableRule struct {
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

func (r *TableRule) Validate() error {
	return validator.ValidateStructFields(r)
}

// ToRule converts a TableRule config into a domain rule.
func (r *TableRule) ToRule(sets map[string]set.Set) (*rule.Rule, error) {
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
