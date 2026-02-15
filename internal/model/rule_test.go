package model

import (
	"fmt"
	"testing"

	"github.com/mazdakn/fwsim/internal/traffic"
	. "github.com/onsi/gomega"
)

func TestEmptyRule(t *testing.T) {
	RegisterTestingT(t)

	rule := NewRule()
	pkts := []*traffic.Packet{
		traffic.NewPacket(
			traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
			traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
		),
		traffic.NewPacket(
			traffic.WithSrcAddr("172.16.0.1"), traffic.WithSrcPort(50000), traffic.WithProto(8),
			traffic.WithDstAddr("2.2.2.2"), traffic.WithDstPort(9999),
		),
		traffic.NewPacket(
			traffic.WithSrcAddr("dead:beef::1"), traffic.WithSrcPort(44444), traffic.WithProto(6),
			traffic.WithDstAddr("cafe::1"), traffic.WithDstPort(80),
		),
		traffic.NewPacket(
			traffic.WithSrcAddr("dead:cafe::1"), traffic.WithSrcPort(30000), traffic.WithProto(64),
			traffic.WithDstAddr("ffff::1"), traffic.WithDstPort(8080),
		),
	}
	for _, pkt := range pkts {
		t.Run(pkt.String(), func(t *testing.T) {
			Expect(rule.Match(pkt)).To(BeTrue())
		})
	}
}

func TestRuleIPFamilyMismatch(t *testing.T) {
	RegisterTestingT(t)

	// IPv6 packet
	pktV6 := traffic.NewPacket(
		traffic.WithSrcAddr("dead:beef::1"), traffic.WithSrcPort(44444), traffic.WithProto(6),
		traffic.WithDstAddr("cafe::1"), traffic.WithDstPort(80),
	)

	// Rules with IPv4 networks should not match IPv6 packets
	ipv4Rules := []*Rule{
		NewRule(WithSrcNet("10.10.10.0/24")),
		NewRule(WithDstNet("1.1.1.1/32")),
		NewRule(WithSrcNet("10.10.10.0/24"), WithDstNet("1.1.1.1/32")),
		NewRule(WithProto(17), WithSrcNet("10.10.10.0/24"), WithDstNet("1.1.1.1/32")),
	}
	for _, r := range ipv4Rules {
		t.Run(fmt.Sprintf("IPv4 rule %v should not match IPv6 packet", r.String()), func(t *testing.T) {
			Expect(r.Match(pktV6)).To(BeFalse())
		})
	}

	// IPv4 packet
	pktV4 := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	// Rules with IPv6 networks should not match IPv4 packets
	ipv6Rules := []*Rule{
		NewRule(WithSrcNet("dead:beef::/64")),
		NewRule(WithDstNet("cafe::/112")),
		NewRule(WithSrcNet("dead:beef::/64"), WithDstNet("cafe::/112")),
		NewRule(WithProto(6), WithSrcNet("dead:beef::/64"), WithDstNet("cafe::/112")),
	}
	for _, r := range ipv6Rules {
		t.Run(fmt.Sprintf("IPv6 rule %v should not match IPv4 packet", r.String()), func(t *testing.T) {
			Expect(r.Match(pktV4)).To(BeFalse())
		})
	}
}

func TestRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	pktShouldMatch := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)
	pktShouldNotMatch := traffic.NewPacket(
		traffic.WithSrcAddr("172.16.0.1"), traffic.WithSrcPort(50000), traffic.WithProto(8),
		traffic.WithDstAddr("2.2.2.2"), traffic.WithDstPort(9999),
	)
	for _, r := range makeCommonRules("10.10.10.0/24", "1.1.1.1/32", 17, 55555, 53) {
		t.Run(fmt.Sprintf("should match %v", r.String()), func(t *testing.T) {
			Expect(r.Match(pktShouldMatch)).To(BeTrue())
		})
		t.Run(fmt.Sprintf("should not match %v", r.String()), func(t *testing.T) {
			Expect(r.Match(pktShouldNotMatch)).To(BeFalse())
		})
	}
}

func TestRuleMatchV6(t *testing.T) {
	RegisterTestingT(t)

	pktShouldMatch := traffic.NewPacket(
		traffic.WithSrcAddr("dead:beef::1"), traffic.WithSrcPort(44444), traffic.WithProto(6),
		traffic.WithDstAddr("cafe::1"), traffic.WithDstPort(80),
	)
	pktShouldNotMatch := traffic.NewPacket(
		traffic.WithSrcAddr("dead:cafe::1"), traffic.WithSrcPort(30000), traffic.WithProto(64),
		traffic.WithDstAddr("ffff::1"), traffic.WithDstPort(8080),
	)
	for _, r := range makeCommonRules("dead:beef::/64", "cafe::/112", 6, 44444, 80) {
		t.Run(fmt.Sprintf("should match %v", r.String()), func(t *testing.T) {
			Expect(r.Match(pktShouldMatch)).To(BeTrue())
		})
		t.Run(fmt.Sprintf("should not match %v", r.String()), func(t *testing.T) {
			Expect(r.Match(pktShouldNotMatch)).To(BeFalse())
		})
	}
}

func TestActionString(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		action   Action
		expected string
	}{
		{Accept, "Accept"},
		{Drop, "Drop"},
		{Action(999), "Undefined(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			Expect(tt.action.String()).To(Equal(tt.expected))
		})
	}
}

func TestActionValidate(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name      string
		action    Action
		shouldErr bool
	}{
		{"Accept is valid", Accept, false},
		{"Drop is valid", Drop, false},
		{"Undefined action is invalid", Action(999), true},
		{"Another undefined action is invalid", Action(-1), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.action.Validate()
			if tt.shouldErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func TestMustParseCIDRPanic(t *testing.T) {
	RegisterTestingT(t)

	tests := []string{
		"invalid-cidr",
		"10.10.10.1",         // Missing prefix length
		"256.256.256.256/32", // Invalid IP
		"not-an-ip/24",
	}

	for _, cidr := range tests {
		t.Run(fmt.Sprintf("should panic on %s", cidr), func(t *testing.T) {
			Expect(func() { MustParseCIDR(cidr) }).To(Panic())
		})
	}
}

func makeCommonRules(srcNet, dstNet string, proto uint8, srcPort, dstPort uint16) []*Rule {
	return []*Rule{
		NewRule(WithProto(proto)),
		NewRule(WithSrcPort(srcPort)),
		NewRule(WithDstPort(dstPort)),
		NewRule(WithSrcNet(srcNet)),
		NewRule(WithDstNet(dstNet)),

		NewRule(WithProto(proto), WithSrcPort(srcPort)),
		NewRule(WithProto(proto), WithDstPort(dstPort)),
		NewRule(WithProto(proto), WithSrcNet(srcNet)),
		NewRule(WithProto(proto), WithDstNet(dstNet)),

		NewRule(WithSrcPort(srcPort), WithDstPort(dstPort)),
		NewRule(WithSrcPort(srcPort), WithSrcNet(srcNet)),
		NewRule(WithSrcPort(srcPort), WithDstNet(dstNet)),

		NewRule(WithDstPort(dstPort), WithSrcNet(srcNet)),
		NewRule(WithDstPort(dstPort), WithDstNet(dstNet)),

		NewRule(WithSrcNet(srcNet), WithDstNet(dstNet)),

		NewRule(WithProto(proto), WithDstPort(dstPort), WithDstNet(dstNet)),
		NewRule(WithSrcPort(srcPort), WithDstPort(dstPort), WithSrcNet(srcNet)),
		NewRule(WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),

		NewRule(WithProto(proto), WithSrcPort(srcPort), WithDstPort(dstPort), WithDstNet(dstNet)),
		NewRule(WithProto(proto), WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),

		NewRule(WithProto(proto), WithSrcPort(srcPort), WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),
	}
}

func TestRuleYAMLMarshaling(t *testing.T) {
	RegisterTestingT(t)

	proto := uint8(17)
	srcPort := uint16(55555)
	dstPort := uint16(53)

	rule := NewRule(
		WithProto(proto),
		WithSrcPort(srcPort),
		WithDstPort(dstPort),
		WithSrcNet("10.10.10.0/24"),
		WithDstNet("1.1.1.1/32"),
	)
	rule.Action = Accept

	// Marshal to YAML
	yamlData, err := rule.MarshalYAML()
	Expect(err).ToNot(HaveOccurred())
	Expect(yamlData).ToNot(BeNil())

	// Verify the marshaled data structure
	yamlMap, ok := yamlData.(ruleYAML)
	Expect(ok).To(BeTrue())
	Expect(yamlMap.SrcNet).To(Equal("10.10.10.0/24"))
	Expect(yamlMap.DstNet).To(Equal("1.1.1.1/32"))
	Expect(*yamlMap.Protocol).To(Equal(proto))
	Expect(*yamlMap.SrcPort).To(Equal(srcPort))
	Expect(*yamlMap.DstPort).To(Equal(dstPort))
	Expect(yamlMap.Action).To(Equal("Accept"))
}

func TestRuleYAMLUnmarshaling(t *testing.T) {
	RegisterTestingT(t)

	// Simulate unmarshal
	var rule Rule
	unmarshalFunc := func(v interface{}) error {
		// Simulate YAML unmarshal by directly setting the ruleYAML struct
		ry := v.(*ruleYAML)
		proto := uint8(7)
		srcPort := uint16(30000)
		dstPort := uint16(80)
		ry.SrcNet = "192.168.1.0/24"
		ry.DstNet = "1.1.1.1/32"
		ry.Protocol = &proto
		ry.SrcPort = &srcPort
		ry.DstPort = &dstPort
		ry.Action = "Drop"
		return nil
	}

	err := rule.UnmarshalYAML(unmarshalFunc)
	Expect(err).ToNot(HaveOccurred())

	Expect(rule.SrcNet).ToNot(BeNil())
	Expect(rule.SrcNet.String()).To(Equal("192.168.1.0/24"))
	Expect(rule.DstNet).ToNot(BeNil())
	Expect(rule.DstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(rule.Protocol).ToNot(BeNil())
	Expect(*rule.Protocol).To(Equal(uint8(7)))
	Expect(rule.SrcPort).ToNot(BeNil())
	Expect(*rule.SrcPort).To(Equal(uint16(30000)))
	Expect(rule.DstPort).ToNot(BeNil())
	Expect(*rule.DstPort).To(Equal(uint16(80)))
	Expect(rule.Action).To(Equal(Drop))
}

func TestActionYAMLMarshaling(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		action   Action
		expected string
	}{
		{Accept, "Accept"},
		{Drop, "Drop"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result, err := tt.action.MarshalYAML()
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal(tt.expected))
		})
	}
}

func TestActionYAMLUnmarshaling(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		input    string
		expected Action
		shouldErr bool
	}{
		{"accept", Accept, false},
		{"Accept", Accept, false},
		{"ACCEPT", Accept, false},
		{"drop", Drop, false},
		{"Drop", Drop, false},
		{"DROP", Drop, false},
		{"invalid", Action(0), true},
		{"", Action(0), true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var action Action
			unmarshalFunc := func(v interface{}) error {
				s := v.(*string)
				*s = tt.input
				return nil
			}

			err := action.UnmarshalYAML(unmarshalFunc)
			if tt.shouldErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(action).To(Equal(tt.expected))
			}
		})
	}
}
