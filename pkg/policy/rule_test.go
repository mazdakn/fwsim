package policy

import (
	"fmt"
	"testing"

	"github.com/mazdakn/fwsim/pkg/traffic"
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
			Expect(rule.match(pkt)).To(BeTrue())
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
			Expect(r.match(pktV6)).To(BeFalse())
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
			Expect(r.match(pktV4)).To(BeFalse())
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
			Expect(r.match(pktShouldMatch)).To(BeTrue())
		})
		t.Run(fmt.Sprintf("should not match %v", r.String()), func(t *testing.T) {
			Expect(r.match(pktShouldNotMatch)).To(BeFalse())
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
			Expect(r.match(pktShouldMatch)).To(BeTrue())
		})
		t.Run(fmt.Sprintf("should not match %v", r.String()), func(t *testing.T) {
			Expect(r.match(pktShouldNotMatch)).To(BeFalse())
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
