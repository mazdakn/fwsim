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
	NegSrcNet  []string      `yaml:"neg_src_net,omitempty" validate:"isValidCIDR"`
	NegDstNet  []string      `yaml:"neg_dst_net,omitempty" validate:"isValidCIDR"`
	NegProto   []proto.Proto `yaml:"neg_proto,omitempty"   validate:"isProtoValid"`
	NegSrcPort []uint16      `yaml:"neg_src_port,omitempty" validate:"isPortValid"`
	NegDstPort []uint16      `yaml:"neg_dst_port,omitempty" validate:"isPortValid"`
	SrcIPSet      string        `yaml:"src_ip_set,omitempty"`
	DstIPSet      string        `yaml:"dst_ip_set,omitempty"`
	SrcPortSet    string        `yaml:"src_port_set,omitempty"`
	DstPortSet    string        `yaml:"dst_port_set,omitempty"`
	NegSrcIPSet   string        `yaml:"neg_src_ip_set,omitempty"`
	NegDstIPSet   string        `yaml:"neg_dst_ip_set,omitempty"`
	NegSrcPortSet string        `yaml:"neg_src_port_set,omitempty"`
	NegDstPortSet string        `yaml:"neg_dst_port_set,omitempty"`
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

	if len(r.NegProto) > 0 {
		mRule.NegProto = set.NewProtoSet()
		for _, proto := range r.NegProto {
			mRule.NegProto.Add(proto)
		}
	}

	if len(r.SrcPort) > 0 {
		mRule.SrcPort = set.NewPortSet()
		for _, port := range r.SrcPort {
			mRule.SrcPort.Add(port)
		}
	}

	if len(r.NegSrcPort) > 0 {
		mRule.NegSrcPort = set.NewPortSet()
		for _, port := range r.NegSrcPort {
			mRule.NegSrcPort.Add(port)
		}
	}

	if len(r.DstPort) > 0 {
		mRule.DstPort = set.NewPortSet()
		for _, port := range r.DstPort {
			mRule.DstPort.Add(port)
		}
	}

	if len(r.NegDstPort) > 0 {
		mRule.NegDstPort = set.NewPortSet()
		for _, port := range r.NegDstPort {
			mRule.NegDstPort.Add(port)
		}
	}

	if len(r.SrcNet) > 0 {
		mRule.SrcNet = set.NewIPSet()
		for _, srcNet := range r.SrcNet {
			mRule.SrcNet.Add(rule.MustParseCIDR(srcNet))
		}
	}

	if len(r.NegSrcNet) > 0 {
		mRule.NegSrcNet = set.NewIPSet()
		for _, srcNet := range r.NegSrcNet {
			mRule.NegSrcNet.Add(rule.MustParseCIDR(srcNet))
		}
	}

	if len(r.DstNet) > 0 {
		mRule.DstNet = set.NewIPSet()
		for _, dstNet := range r.DstNet {
			mRule.DstNet.Add(rule.MustParseCIDR(dstNet))
		}
	}

	if len(r.NegDstNet) > 0 {
		mRule.NegDstNet = set.NewIPSet()
		for _, dstNet := range r.NegDstNet {
			mRule.NegDstNet.Add(rule.MustParseCIDR(dstNet))
		}
	}

	if r.SrcIPSet != "" {
		s, ok := sets[r.SrcIPSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.SrcIPSet)
		}
		mRule.SrcIPSet = s
	}

	if r.DstIPSet != "" {
		s, ok := sets[r.DstIPSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.DstIPSet)
		}
		mRule.DstIPSet = s
	}

	if r.SrcPortSet != "" {
		s, ok := sets[r.SrcPortSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.SrcPortSet)
		}
		mRule.SrcPortSet = s
	}

	if r.DstPortSet != "" {
		s, ok := sets[r.DstPortSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.DstPortSet)
		}
		mRule.DstPortSet = s
	}

	if r.NegSrcIPSet != "" {
		s, ok := sets[r.NegSrcIPSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.NegSrcIPSet)
		}
		mRule.NegSrcIPSet = s
	}

	if r.NegDstIPSet != "" {
		s, ok := sets[r.NegDstIPSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.NegDstIPSet)
		}
		mRule.NegDstIPSet = s
	}

	if r.NegSrcPortSet != "" {
		s, ok := sets[r.NegSrcPortSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.NegSrcPortSet)
		}
		mRule.NegSrcPortSet = s
	}

	if r.NegDstPortSet != "" {
		s, ok := sets[r.NegDstPortSet]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown set %q", r.Name, r.NegDstPortSet)
		}
		mRule.NegDstPortSet = s
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
