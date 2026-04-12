package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type RuleConfig struct {
	Rules         []Rule `yaml:"rules,omitempty"`
	DefaultAction string `yaml:"default_action,omitempty" validate:"isValidAction"`
}

func (rc *RuleConfig) Validate() error {
	return validator.ValidateStructFields(rc)
}

// Rule represents the YAML configuration structure for a firewall rule.
type Rule struct {
	Name       string        `yaml:"name,omitempty"`
	Order      uint64        `yaml:"order,omitempty"`
	SrcNet     []string      `yaml:"src_net,omitempty"     validate:"isValidCIDR"`
	DstNet     []string      `yaml:"dst_net,omitempty"     validate:"isValidCIDR"`
	Protocol   []proto.Proto `yaml:"proto,omitempty"       validate:"isProtoValid"`
	SrcPort    []uint16      `yaml:"src_port,omitempty"    validate:"isPortValid"`
	DstPort    []uint16      `yaml:"dst_port,omitempty"    validate:"isPortValid"`
	NotSrcNet  []string      `yaml:"not_src_net,omitempty" validate:"isValidCIDR"`
	NotDstNet  []string      `yaml:"not_dst_net,omitempty" validate:"isValidCIDR"`
	NotProto   []proto.Proto `yaml:"not_proto,omitempty"   validate:"isProtoValid"`
	NotSrcPort []uint16      `yaml:"not_src_port,omitempty" validate:"isPortValid"`
	NotDstPort []uint16      `yaml:"not_dst_port,omitempty" validate:"isPortValid"`
	SrcIPSet      string        `yaml:"src_ip_set,omitempty"`
	DstIPSet      string        `yaml:"dst_ip_set,omitempty"`
	SrcPortSet    string        `yaml:"src_port_set,omitempty"`
	DstPortSet    string        `yaml:"dst_port_set,omitempty"`
	NotSrcIPSet   string        `yaml:"not_src_ip_set,omitempty"`
	NotDstIPSet   string        `yaml:"not_dst_ip_set,omitempty"`
	NotSrcPortSet string        `yaml:"not_src_port_set,omitempty"`
	NotDstPortSet string        `yaml:"not_dst_port_set,omitempty"`
	Action     string        `yaml:"action,omitempty"      validate:"isValidAction"`
}

// ToRule converts a RuleConfig into a Rule domain object.
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
			mRule.Proto.Add(proto)
		}
	}

	if len(r.NotProto) > 0 {
		mRule.NotProto = set.NewProtoSet()
		for _, proto := range r.NotProto {
			mRule.NotProto.Add(proto)
		}
	}

	if len(r.SrcPort) > 0 {
		mRule.Source.Port = set.NewPortSet()
		for _, port := range r.SrcPort {
			mRule.Source.Port.Add(port)
		}
	}

	if len(r.NotSrcPort) > 0 {
		mRule.NotSource.Port = set.NewPortSet()
		for _, port := range r.NotSrcPort {
			mRule.NotSource.Port.Add(port)
		}
	}

	if len(r.DstPort) > 0 {
		mRule.Destination.Port = set.NewPortSet()
		for _, port := range r.DstPort {
			mRule.Destination.Port.Add(port)
		}
	}

	if len(r.NotDstPort) > 0 {
		mRule.NotDestination.Port = set.NewPortSet()
		for _, port := range r.NotDstPort {
			mRule.NotDestination.Port.Add(port)
		}
	}

	if len(r.SrcNet) > 0 {
		mRule.Source.Net = set.NewIPSet()
		for _, srcNet := range r.SrcNet {
			mRule.Source.Net.Add(rule.MustParseCIDR(srcNet))
		}
	}

	if len(r.NotSrcNet) > 0 {
		mRule.NotSource.Net = set.NewIPSet()
		for _, srcNet := range r.NotSrcNet {
			mRule.NotSource.Net.Add(rule.MustParseCIDR(srcNet))
		}
	}

	if len(r.DstNet) > 0 {
		mRule.Destination.Net = set.NewIPSet()
		for _, dstNet := range r.DstNet {
			mRule.Destination.Net.Add(rule.MustParseCIDR(dstNet))
		}
	}

	if len(r.NotDstNet) > 0 {
		mRule.NotDestination.Net = set.NewIPSet()
		for _, dstNet := range r.NotDstNet {
			mRule.NotDestination.Net.Add(rule.MustParseCIDR(dstNet))
		}
	}

	if r.SrcIPSet != "" {
		s, ok := sets[r.SrcIPSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.SrcIPSet)
		}
		mRule.Source.IPSet = s
	}

	if r.DstIPSet != "" {
		s, ok := sets[r.DstIPSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.DstIPSet)
		}
		mRule.Destination.IPSet = s
	}

	if r.SrcPortSet != "" {
		s, ok := sets[r.SrcPortSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.SrcPortSet)
		}
		mRule.Source.PortSet = s
	}

	if r.DstPortSet != "" {
		s, ok := sets[r.DstPortSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.DstPortSet)
		}
		mRule.Destination.PortSet = s
	}

	if r.NotSrcIPSet != "" {
		s, ok := sets[r.NotSrcIPSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.NotSrcIPSet)
		}
		mRule.NotSource.IPSet = s
	}

	if r.NotDstIPSet != "" {
		s, ok := sets[r.NotDstIPSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.NotDstIPSet)
		}
		mRule.NotDestination.IPSet = s
	}

	if r.NotSrcPortSet != "" {
		s, ok := sets[r.NotSrcPortSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.NotSrcPortSet)
		}
		mRule.NotSource.PortSet = s
	}

	if r.NotDstPortSet != "" {
		s, ok := sets[r.NotDstPortSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.NotDstPortSet)
		}
		mRule.NotDestination.PortSet = s
	}

	return mRule, nil
}

func RuleConfigFromBytes(data []byte) (*RuleConfig, error) {
	var rc RuleConfig
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return nil, err
	}
	if err := rc.Validate(); err != nil {
		return nil, err
	}
	return &rc, nil
}

func RuleConfigFromFile(file string) (*RuleConfig, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return RuleConfigFromBytes(data)
}
