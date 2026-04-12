package rule

import (
	"fmt"
	"sync"
	"testing"

	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/set"
	. "github.com/onsi/gomega"
)

func TestEmptyRule(t *testing.T) {
	RegisterTestingT(t)

	rule := New()
	pkts := []*packet.Packet{
		packet.New(
			packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
			packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
		),
		packet.New(
			packet.WithSrcAddr("172.16.0.1"), packet.WithSrcPort(50000), packet.WithProto(proto.Proto(8)),
			packet.WithDstAddr("2.2.2.2"), packet.WithDstPort(9999),
		),
		packet.New(
			packet.WithSrcAddr("dead:beef::1"), packet.WithSrcPort(44444), packet.WithProto(proto.TCP),
			packet.WithDstAddr("cafe::1"), packet.WithDstPort(80),
		),
		packet.New(
			packet.WithSrcAddr("dead:cafe::1"), packet.WithSrcPort(30000), packet.WithProto(proto.Proto(64)),
			packet.WithDstAddr("ffff::1"), packet.WithDstPort(8080),
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
	pktV6 := packet.New(
		packet.WithSrcAddr("dead:beef::1"), packet.WithSrcPort(44444), packet.WithProto(proto.TCP),
		packet.WithDstAddr("cafe::1"), packet.WithDstPort(80),
	)

	// Rules with IPv4 networks should not match IPv6 packets
	ipv4Rules := []*Rule{
		New(WithSrcNet("10.10.10.0/24")),
		New(WithDstNet("1.1.1.1/32")),
		New(WithSrcNet("10.10.10.0/24"), WithDstNet("1.1.1.1/32")),
		New(WithProto(proto.UDP), WithSrcNet("10.10.10.0/24"), WithDstNet("1.1.1.1/32")),
	}
	for _, r := range ipv4Rules {
		t.Run(fmt.Sprintf("IPv4 rule %v should not match IPv6 packet", r.String()), func(t *testing.T) {
			Expect(r.Match(pktV6)).To(BeFalse())
		})
	}

	// IPv4 packet
	pktV4 := packet.New(
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)

	// Rules with IPv6 networks should not match IPv4 packets
	ipv6Rules := []*Rule{
		New(WithSrcNet("dead:beef::/64")),
		New(WithDstNet("cafe::/112")),
		New(WithSrcNet("dead:beef::/64"), WithDstNet("cafe::/112")),
		New(WithProto(proto.TCP), WithSrcNet("dead:beef::/64"), WithDstNet("cafe::/112")),
	}
	for _, r := range ipv6Rules {
		t.Run(fmt.Sprintf("IPv6 rule %v should not match IPv4 packet", r.String()), func(t *testing.T) {
			Expect(r.Match(pktV4)).To(BeFalse())
		})
	}
}

func TestRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	pktShouldMatch := packet.New(
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)
	pktShouldNotMatch := packet.New(
		packet.WithSrcAddr("172.16.0.1"), packet.WithSrcPort(50000), packet.WithProto(proto.Proto(8)),
		packet.WithDstAddr("2.2.2.2"), packet.WithDstPort(9999),
	)
	for _, r := range makeCommonRules("10.10.10.0/24", "1.1.1.1/32", proto.UDP, 55555, 53) {
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

	pktShouldMatch := packet.New(
		packet.WithSrcAddr("dead:beef::1"), packet.WithSrcPort(44444), packet.WithProto(proto.TCP),
		packet.WithDstAddr("cafe::1"), packet.WithDstPort(80),
	)
	pktShouldNotMatch := packet.New(
		packet.WithSrcAddr("dead:cafe::1"), packet.WithSrcPort(30000), packet.WithProto(proto.Proto(64)),
		packet.WithDstAddr("ffff::1"), packet.WithDstPort(8080),
	)
	for _, r := range makeCommonRules("dead:beef::/64", "cafe::/112", proto.TCP, 44444, 80) {
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

func makeCommonRules(srcNet, dstNet string, p proto.Proto, srcPort, dstPort uint16) []*Rule {
	return []*Rule{
		New(WithProto(p)),
		New(WithSrcPort(srcPort)),
		New(WithDstPort(dstPort)),
		New(WithSrcNet(srcNet)),
		New(WithDstNet(dstNet)),

		New(WithProto(p), WithSrcPort(srcPort)),
		New(WithProto(p), WithDstPort(dstPort)),
		New(WithProto(p), WithSrcNet(srcNet)),
		New(WithProto(p), WithDstNet(dstNet)),

		New(WithSrcPort(srcPort), WithDstPort(dstPort)),
		New(WithSrcPort(srcPort), WithSrcNet(srcNet)),
		New(WithSrcPort(srcPort), WithDstNet(dstNet)),

		New(WithDstPort(dstPort), WithSrcNet(srcNet)),
		New(WithDstPort(dstPort), WithDstNet(dstNet)),

		New(WithSrcNet(srcNet), WithDstNet(dstNet)),

		New(WithProto(p), WithDstPort(dstPort), WithDstNet(dstNet)),
		New(WithSrcPort(srcPort), WithDstPort(dstPort), WithSrcNet(srcNet)),
		New(WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),

		New(WithProto(p), WithSrcPort(srcPort), WithDstPort(dstPort), WithDstNet(dstNet)),
		New(WithProto(p), WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),

		New(WithProto(p), WithSrcPort(srcPort), WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),
	}
}

func TestParseAction(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		input     string
		expected  Action
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
		{"deny", Action(0), true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			action, err := ParseAction(tt.input)
			if tt.shouldErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(action).To(Equal(tt.expected))
			}
		})
	}
}

func TestRulePacketCounter(t *testing.T) {
	RegisterTestingT(t)

	rule := New(WithProto(proto.UDP), WithDstPort(53))
	pktMatch := packet.New(
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)
	pktNoMatch := packet.New(
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
	)

	// Initially, packet count should be 0
	Expect(rule.PacketCount()).To(Equal(uint64(0)))

	// Match a packet, count should increment to 1
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.PacketCount()).To(Equal(uint64(1)))

	// Match another packet, count should increment to 2
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.PacketCount()).To(Equal(uint64(2)))

	// Non-matching packet should not increment counter
	Expect(rule.Match(pktNoMatch)).To(BeFalse())
	Expect(rule.PacketCount()).To(Equal(uint64(2)))

	// Reset counter
	rule.ResetPacketCount()
	Expect(rule.PacketCount()).To(Equal(uint64(0)))

	// Match after reset should increment from 0
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.PacketCount()).To(Equal(uint64(1)))
}

func TestRulePacketCounterConcurrency(t *testing.T) {
	RegisterTestingT(t)

	rule := New(WithProto(proto.UDP), WithDstPort(53))
	pktMatch := packet.New(
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)

	// Concurrently match packets to test thread-safety
	numGoroutines := 100
	matchesPerGoroutine := 100
	expectedCount := uint64(numGoroutines * matchesPerGoroutine)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < matchesPerGoroutine; j++ {
				rule.Match(pktMatch)
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Verify the counter is correct
	Expect(rule.PacketCount()).To(Equal(expectedCount))
}

func TestRuleWithName(t *testing.T) {
	RegisterTestingT(t)

	// Rule without name should use the full rule representation
	ruleNoName := New(WithAction(Accept), WithProto(proto.TCP), WithDstPort(80))
	Expect(ruleNoName.String()).To(Equal("Accept tcp{*:*->*:80}"))

	// Rule with name should use the name for output
	ruleWithName := New(WithAction(Accept), WithProto(proto.TCP), WithDstPort(80), WithName("allow-http"))
	Expect(ruleWithName.String()).To(Equal("allow-http"))

	// Setting Name directly should also work
	ruleDirectName := New(WithAction(Drop))
	ruleDirectName.Name = "block-all"
	Expect(ruleDirectName.String()).To(Equal("block-all"))
}

func TestNegatedRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// Packet that will be matched against negated rules
	pkt := packet.New(
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)

	// Negated protocol: should NOT match proto 17, but SHOULD match everything else
	ruleNegProto := New(WithNegProto(proto.UDP))
	Expect(ruleNegProto.Match(pkt)).To(BeFalse())

	ruleNegProtoOther := New(WithNegProto(proto.TCP))
	Expect(ruleNegProtoOther.Match(pkt)).To(BeTrue())

	// Negated source port: should NOT match src port 55555
	ruleNegSrcPort := New(WithNegSrcPort(55555))
	Expect(ruleNegSrcPort.Match(pkt)).To(BeFalse())

	ruleNegSrcPortOther := New(WithNegSrcPort(12345))
	Expect(ruleNegSrcPortOther.Match(pkt)).To(BeTrue())

	// Negated destination port: should NOT match dst port 53
	ruleNegDstPort := New(WithNegDstPort(53))
	Expect(ruleNegDstPort.Match(pkt)).To(BeFalse())

	ruleNegDstPortOther := New(WithNegDstPort(80))
	Expect(ruleNegDstPortOther.Match(pkt)).To(BeTrue())

	// Negated source network: should NOT match 10.10.10.0/24
	ruleNegSrcNet := New(WithNegSrcNet("10.10.10.0/24"))
	Expect(ruleNegSrcNet.Match(pkt)).To(BeFalse())

	ruleNegSrcNetOther := New(WithNegSrcNet("192.168.0.0/16"))
	Expect(ruleNegSrcNetOther.Match(pkt)).To(BeTrue())

	// Negated destination network: should NOT match 1.1.1.1/32
	ruleNegDstNet := New(WithNegDstNet("1.1.1.1/32"))
	Expect(ruleNegDstNet.Match(pkt)).To(BeFalse())

	ruleNegDstNetOther := New(WithNegDstNet("2.2.2.2/32"))
	Expect(ruleNegDstNetOther.Match(pkt)).To(BeTrue())
}

func TestNegatedRuleString(t *testing.T) {
	RegisterTestingT(t)

	// Negated proto should show with ! prefix
	ruleNegProto := New(WithAction(Accept), WithNegProto(proto.TCP))
	Expect(ruleNegProto.String()).To(Equal("Accept !tcp{*:*->*:*}"))

	// Negated src port should show with ! prefix
	ruleNegSrcPort := New(WithAction(Drop), WithNegSrcPort(80))
	Expect(ruleNegSrcPort.String()).To(Equal("Drop *{*:!80->*:*}"))

	// Negated dst port should show with ! prefix
	ruleNegDstPort := New(WithAction(Accept), WithNegDstPort(53))
	Expect(ruleNegDstPort.String()).To(Equal("Accept *{*:*->*:!53}"))

	// Negated src net should show with ! prefix
	ruleNegSrcNet := New(WithAction(Drop), WithNegSrcNet("10.0.0.0/8"))
	Expect(ruleNegSrcNet.String()).To(Equal("Drop *{!10.0.0.0/8:*->*:*}"))

	// Negated dst net should show with ! prefix
	ruleNegDstNet := New(WithAction(Accept), WithNegDstNet("1.1.1.1/32"))
	Expect(ruleNegDstNet.String()).To(Equal("Accept *{*:*->!1.1.1.1/32:*}"))
}

func TestNegatedRuleConfig(t *testing.T) {
	RegisterTestingT(t)

	// Valid negated rule — negated fields populate dedicated Rule fields
	rule := New(
		WithAction(Accept),
		WithNegProto(proto.TCP),
		WithNegSrcPort(80),
		WithNegDstPort(443),
		WithNegSrcNet("10.0.0.0/8"),
		WithNegDstNet("192.168.0.0/16"),
	)
	Expect(rule.NegProto).ToNot(BeNil())
	Expect(rule.NegSrcPort).ToNot(BeNil())
	Expect(rule.NegDstPort).ToNot(BeNil())
	Expect(rule.NegSrcNet).ToNot(BeNil())
	Expect(rule.NegDstNet).ToNot(BeNil())
	// Positive fields should be nil when only negated values are specified
	Expect(rule.Proto).To(BeNil())
	Expect(rule.Source.Port).To(BeNil())
	Expect(rule.DstPort).To(BeNil())
	Expect(rule.Source.Net).To(BeNil())
	Expect(rule.DstNet).To(BeNil())

	// Positive and negated fields can be combined on the same rule
	ruleCombined := New(
		WithAction(Accept),
		WithProto(proto.UDP),
		WithNegProto(proto.TCP),
		WithSrcPort(12345),
		WithNegSrcPort(80),
		WithDstPort(53),
		WithNegDstPort(443),
		WithSrcNet("10.0.0.0/8"),
		WithNegSrcNet("10.10.0.0/16"),
		WithDstNet("1.1.1.0/24"),
		WithNegDstNet("1.1.1.100/32"),
	)
	Expect(ruleCombined.Proto).ToNot(BeNil())
	Expect(ruleCombined.NegProto).ToNot(BeNil())
	Expect(ruleCombined.Source.Port).ToNot(BeNil())
	Expect(ruleCombined.NegSrcPort).ToNot(BeNil())
	Expect(ruleCombined.DstPort).ToNot(BeNil())
	Expect(ruleCombined.NegDstPort).ToNot(BeNil())
	Expect(ruleCombined.Source.Net).ToNot(BeNil())
	Expect(ruleCombined.NegSrcNet).ToNot(BeNil())
	Expect(ruleCombined.DstNet).ToNot(BeNil())
	Expect(ruleCombined.NegDstNet).ToNot(BeNil())
}

func TestCombinedPositiveAndNegativeRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// Rule matches src in 10.0.0.0/8 but NOT in 10.10.0.0/16
	rule := New(WithSrcNet("10.0.0.0/8"), WithNegSrcNet("10.10.0.0/16"))

	// In 10.0.0.0/8, not in 10.10.0.0/16 → should match
	pktMatch := packet.New(packet.WithSrcAddr("10.1.2.3"))
	Expect(rule.Match(pktMatch)).To(BeTrue())

	// In 10.0.0.0/8 AND in 10.10.0.0/16 → should not match (excluded by neg)
	pktNegHit := packet.New(packet.WithSrcAddr("10.10.0.5"))
	Expect(rule.Match(pktNegHit)).To(BeFalse())

	// Not in 10.0.0.0/8 at all → should not match (excluded by positive)
	pktOutside := packet.New(packet.WithSrcAddr("172.16.0.1"))
	Expect(rule.Match(pktOutside)).To(BeFalse())

	// Rule matches proto 17 AND NOT proto 6 (proto 6 is excluded, proto 17 is required)
	ruleProto := New(WithProto(proto.UDP), WithNegProto(proto.TCP))
	pktProto17 := packet.New(packet.WithProto(proto.UDP))
	pktProto6 := packet.New(packet.WithProto(proto.TCP))
	pktProto1 := packet.New(packet.WithProto(proto.ICMP))
	Expect(ruleProto.Match(pktProto17)).To(BeTrue())
	Expect(ruleProto.Match(pktProto6)).To(BeFalse())
	Expect(ruleProto.Match(pktProto1)).To(BeFalse()) // not in positive set
}

func TestCombinedRuleString(t *testing.T) {
	RegisterTestingT(t)

	// Combined proto field
	ruleBoth := New(WithAction(Accept), WithProto(proto.UDP), WithNegProto(proto.TCP))
	Expect(ruleBoth.String()).To(Equal("Accept udp,!tcp{*:*->*:*}"))

	// Combined src net field
	ruleSrcNet := New(WithAction(Drop), WithSrcNet("10.0.0.0/8"), WithNegSrcNet("10.10.0.0/16"))
	Expect(ruleSrcNet.String()).To(Equal("Drop *{10.0.0.0/8,!10.10.0.0/16:*->*:*}"))
}

func TestNamedSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("10.0.0.0/8")

	portSet := set.NewPortSet()
	_ = portSet.Add(uint16(80))

	pktMatch := packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
	)
	pktNoMatchIP := packet.New(
		packet.WithSrcAddr("192.168.1.1"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
	)
	pktNoMatchPort := packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	)

	r := New(WithSrcIPSet(ipSet), WithDstPortSet(portSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatchIP)).To(BeFalse())
	Expect(r.Match(pktNoMatchPort)).To(BeFalse())
}

func TestNamedSetRuleMatchDstIPSet(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("1.1.1.0/24")

	pktMatch := packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithDstAddr("1.1.1.1"),
	)
	pktNoMatch := packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithDstAddr("2.2.2.2"),
	)

	r := New(WithDstIPSet(ipSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestNamedSetRuleMatchSrcPortSet(t *testing.T) {
	RegisterTestingT(t)

	portSet := set.NewPortSet()
	_ = portSet.Add(uint16(55555))

	pktMatch := packet.New(
		packet.WithSrcPort(55555),
	)
	pktNoMatch := packet.New(
		packet.WithSrcPort(12345),
	)

	r := New(WithSrcPortSet(portSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestNegatedNamedSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// NegSrcIPSet: packets whose source is in the set should NOT match.
	srcIPSet := set.NewIPSet()
	_ = srcIPSet.Add("10.0.0.0/8")

	rNegSrc := New(WithNegSrcIPSet(srcIPSet))
	pktInSet := packet.New(packet.WithSrcAddr("10.1.2.3"))
	pktOutSet := packet.New(packet.WithSrcAddr("192.168.1.1"))
	Expect(rNegSrc.Match(pktInSet)).To(BeFalse())
	Expect(rNegSrc.Match(pktOutSet)).To(BeTrue())

	// NegDstIPSet: packets whose destination is in the set should NOT match.
	dstIPSet := set.NewIPSet()
	_ = dstIPSet.Add("1.1.1.0/24")

	rNegDst := New(WithNegDstIPSet(dstIPSet))
	pktDstIn := packet.New(packet.WithDstAddr("1.1.1.1"))
	pktDstOut := packet.New(packet.WithDstAddr("2.2.2.2"))
	Expect(rNegDst.Match(pktDstIn)).To(BeFalse())
	Expect(rNegDst.Match(pktDstOut)).To(BeTrue())

	// NegSrcPortSet: packets whose source port is in the set should NOT match.
	srcPortSet := set.NewPortSet()
	_ = srcPortSet.Add(uint16(55555))

	rNegSrcPort := New(WithNegSrcPortSet(srcPortSet))
	pktSrcPortIn := packet.New(packet.WithSrcPort(55555))
	pktSrcPortOut := packet.New(packet.WithSrcPort(12345))
	Expect(rNegSrcPort.Match(pktSrcPortIn)).To(BeFalse())
	Expect(rNegSrcPort.Match(pktSrcPortOut)).To(BeTrue())

	// NegDstPortSet: packets whose destination port is in the set should NOT match.
	dstPortSet := set.NewPortSet()
	_ = dstPortSet.Add(uint16(80))

	rNegDstPort := New(WithNegDstPortSet(dstPortSet))
	pktDstPortIn := packet.New(packet.WithDstPort(80))
	pktDstPortOut := packet.New(packet.WithDstPort(443))
	Expect(rNegDstPort.Match(pktDstPortIn)).To(BeFalse())
	Expect(rNegDstPort.Match(pktDstPortOut)).To(BeTrue())
}

func TestCombinedPositiveAndNegativeNamedSetMatch(t *testing.T) {
	RegisterTestingT(t)

	// Match src in 10.0.0.0/8 named set but NOT in 10.10.0.0/16 named set.
	posSet := set.NewIPSet()
	_ = posSet.Add("10.0.0.0/8")

	negSet := set.NewIPSet()
	_ = negSet.Add("10.10.0.0/16")

	r := New(WithSrcIPSet(posSet), WithNegSrcIPSet(negSet))

	// In 10.0.0.0/8, not in 10.10.0.0/16 → should match
	Expect(r.Match(packet.New(packet.WithSrcAddr("10.1.2.3")))).To(BeTrue())
	// In 10.0.0.0/8 AND in 10.10.0.0/16 → excluded by neg
	Expect(r.Match(packet.New(packet.WithSrcAddr("10.10.0.5")))).To(BeFalse())
	// Not in 10.0.0.0/8 at all → excluded by positive
	Expect(r.Match(packet.New(packet.WithSrcAddr("172.16.0.1")))).To(BeFalse())
}

func TestNegatedNamedSetRuleString(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("10.0.0.0/8")

	portSet := set.NewPortSet()
	_ = portSet.Add(uint16(80))

	// NegSrcIPSet only → srcNet shows as !10.0.0.0/8
	rNegSrcIP := New(WithAction(Accept), WithNegSrcIPSet(ipSet))
	Expect(rNegSrcIP.String()).To(Equal("Accept *{!10.0.0.0/8:*->*:*}"))

	// NegDstPortSet only → dstPort shows as !80
	rNegDstPort := New(WithAction(Drop), WithNegDstPortSet(portSet))
	Expect(rNegDstPort.String()).To(Equal("Drop *{*:*->*:!80}"))
}
