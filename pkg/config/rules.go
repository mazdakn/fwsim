package config

import (
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
	Action     string        `yaml:"action,omitempty"      validate:"isValidAction"`
}

// ToRule converts a RuleConfig into a Rule domain object.
func (r *Rule) ToRule() *rule.Rule {
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

	return mRule
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
