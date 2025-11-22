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
