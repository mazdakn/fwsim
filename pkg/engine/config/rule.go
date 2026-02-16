package config

import (
	"fmt"
	"net"
)

// RuleYAML is a helper struct for YAML marshaling/unmarshaling
type RuleYAML struct {
	SrcNet   string  `yaml:"src_net,omitempty"`
	DstNet   string  `yaml:"dst_net,omitempty"`
	Protocol *uint8  `yaml:"proto,omitempty"`
	SrcPort  *uint16 `yaml:"src_port,omitempty"`
	DstPort  *uint16 `yaml:"dst_port,omitempty"`
	Action   string  `yaml:"action,omitempty"`
}

// UnmarshalRuleFromYAML contains the unmarshaling logic for Rule
// This is called by Rule.UnmarshalYAML in internal/model
func UnmarshalRuleFromYAML(unmarshal func(interface{}) error) (*RuleYAML, error) {
	var ry RuleYAML
	if err := unmarshal(&ry); err != nil {
		return nil, err
	}
	return &ry, nil
}

// ParseRuleYAML converts RuleYAML data to Rule fields
func ParseRuleYAML(ry *RuleYAML) (srcNet, dstNet *net.IPNet, protocol *uint8, srcPort, dstPort *uint16, actionStr string, err error) {
	// Parse SrcNet
	if ry.SrcNet != "" {
		_, ipnet, parseErr := net.ParseCIDR(ry.SrcNet)
		if parseErr != nil {
			err = fmt.Errorf("invalid src_net %s: %w", ry.SrcNet, parseErr)
			return
		}
		srcNet = ipnet
	}

	// Parse DstNet
	if ry.DstNet != "" {
		_, ipnet, parseErr := net.ParseCIDR(ry.DstNet)
		if parseErr != nil {
			err = fmt.Errorf("invalid dst_net %s: %w", ry.DstNet, parseErr)
			return
		}
		dstNet = ipnet
	}

	// Copy other fields
	protocol = ry.Protocol
	srcPort = ry.SrcPort
	dstPort = ry.DstPort
	actionStr = ry.Action

	return
}

// MarshalRuleToYAML converts Rule fields to RuleYAML for marshaling
func MarshalRuleToYAML(srcNet, dstNet *net.IPNet, protocol *uint8, srcPort, dstPort *uint16, actionStr string) interface{} {
	ry := RuleYAML{
		Protocol: protocol,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Action:   actionStr,
	}

	if srcNet != nil {
		ry.SrcNet = srcNet.String()
	}
	if dstNet != nil {
		ry.DstNet = dstNet.String()
	}

	return ry
}

