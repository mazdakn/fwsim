package model

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mazdakn/fwsim/internal/traffic"
)

type Action int

const (
	Accept Action = iota
	Drop
)

func (a Action) String() string {
	switch a {
	case Accept:
		return "Accept"
	case Drop:
		return "Drop"
	default:
		return fmt.Sprintf("Undefined(%d)", a)
	}
}

func (a Action) Validate() error {
	switch a {
	case Accept, Drop:
		return nil
	default:
		return fmt.Errorf("undefined action %v", a)
	}
}

func (a *Action) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	action, err := ParseAction(s)
	if err != nil {
		return err
	}
	*a = action
	return nil
}

func (a Action) MarshalYAML() (interface{}, error) {
	return a.String(), nil
}

// ParseAction parses an action string into an Action type
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "accept":
		return Accept, nil
	case "drop":
		return Drop, nil
	default:
		return Action(0), fmt.Errorf("unknown action: %s", s)
	}
}

type RuleOption func(*Rule)

func WithProto(proto uint8) RuleOption {
	return func(r *Rule) {
		r.Protocol = &proto
	}
}

func WithSrcPort(port uint16) RuleOption {
	return func(r *Rule) {
		r.SrcPort = &port
	}
}

func WithDstPort(port uint16) RuleOption {
	return func(r *Rule) {
		r.DstPort = &port
	}
}

func WithSrcNet(cidr string) RuleOption {
	return func(r *Rule) {
		r.SrcNet = MustParseCIDR(cidr)
	}
}

func WithDstNet(cidr string) RuleOption {
	return func(r *Rule) {
		r.DstNet = MustParseCIDR(cidr)
	}
}

func NewRule(opts ...RuleOption) *Rule {
	var r Rule
	for _, o := range opts {
		o(&r)
	}
	return &r
}

type Rule struct {
	SrcNet   *net.IPNet
	DstNet   *net.IPNet
	Protocol *uint8

	SrcPort *uint16
	DstPort *uint16

	Action Action
}

func (r *Rule) Match(pkt *traffic.Packet) bool {
	if r.Protocol != nil && *r.Protocol != pkt.Protocol {
		return false
	}
	if r.SrcPort != nil && *r.SrcPort != pkt.SrcPort {
		return false
	}
	if r.DstPort != nil && *r.DstPort != pkt.DstPort {
		return false
	}
	if r.SrcNet != nil && !r.SrcNet.Contains(pkt.SrcAddr) {
		return false
	}
	if r.DstNet != nil && !r.DstNet.Contains(pkt.DstAddr) {
		return false
	}
	return true
}

func (r *Rule) String() string {
	proto := "*"
	if r.Protocol != nil {
		proto = strconv.Itoa(int(*r.Protocol))
	}
	srcPort := "*"
	if r.SrcPort != nil {
		srcPort = strconv.Itoa(int(*r.SrcPort))
	}
	dstPort := "*"
	if r.DstPort != nil {
		dstPort = strconv.Itoa(int(*r.DstPort))
	}
	srcNet := "*"
	if r.SrcNet != nil {
		srcNet = r.SrcNet.String()
	}
	dstNet := "*"
	if r.DstNet != nil {
		dstNet = r.DstNet.String()
	}
	return fmt.Sprintf("%s{%s:%s->%s:%s}", proto, srcNet, srcPort, dstNet, dstPort)
}

func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("CIDR %s is invalid", cidr))
	}
	return ipnet
}

// ruleYAML is a helper struct for YAML marshaling/unmarshaling
type ruleYAML struct {
	SrcNet   string  `yaml:"src_net,omitempty"`
	DstNet   string  `yaml:"dst_net,omitempty"`
	Protocol *uint8  `yaml:"proto,omitempty"`
	SrcPort  *uint16 `yaml:"src_port,omitempty"`
	DstPort  *uint16 `yaml:"dst_port,omitempty"`
	Action   string  `yaml:"action,omitempty"`
}

func (r *Rule) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var ry ruleYAML
	if err := unmarshal(&ry); err != nil {
		return err
	}

	// Parse SrcNet
	if ry.SrcNet != "" {
		_, ipnet, err := net.ParseCIDR(ry.SrcNet)
		if err != nil {
			return fmt.Errorf("invalid src_net %s: %w", ry.SrcNet, err)
		}
		r.SrcNet = ipnet
	}

	// Parse DstNet
	if ry.DstNet != "" {
		_, ipnet, err := net.ParseCIDR(ry.DstNet)
		if err != nil {
			return fmt.Errorf("invalid dst_net %s: %w", ry.DstNet, err)
		}
		r.DstNet = ipnet
	}

	// Copy other fields
	r.Protocol = ry.Protocol
	r.SrcPort = ry.SrcPort
	r.DstPort = ry.DstPort

	// Parse Action using the helper function
	action, err := ParseAction(ry.Action)
	if err != nil {
		return err
	}
	r.Action = action

	return nil
}

func (r Rule) MarshalYAML() (interface{}, error) {
	ry := ruleYAML{
		Protocol: r.Protocol,
		SrcPort:  r.SrcPort,
		DstPort:  r.DstPort,
		Action:   r.Action.String(),
	}

	if r.SrcNet != nil {
		ry.SrcNet = r.SrcNet.String()
	}
	if r.DstNet != nil {
		ry.DstNet = r.DstNet.String()
	}

	return ry, nil
}
