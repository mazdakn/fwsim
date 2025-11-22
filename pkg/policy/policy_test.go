package policy

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/traffic"
	. "github.com/onsi/gomega"
)

func TestNewStore(t *testing.T) {
	RegisterTestingT(t)

	store := NewStore()
	Expect(store).ToNot(BeNil())
	Expect(store.rules).To(BeEmpty())
}

func TestStoreMatchNoRules(t *testing.T) {
	RegisterTestingT(t)

	store := NewStore()
	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := store.Match(pkt)
	Expect(idx).To(Equal(-1))
	Expect(rule).To(BeNil())
}

func TestStoreMatchSingleRule(t *testing.T) {
	RegisterTestingT(t)

	store := NewStore()
	store.rules = []Rule{
		*NewRule(WithProto(17), WithDstPort(53)),
	}

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := store.Match(pkt)
	Expect(idx).To(Equal(0))
	Expect(rule).ToNot(BeNil())
	Expect(*rule.DstPort).To(Equal(uint16(53)))
	Expect(*rule.Protocol).To(Equal(uint8(17)))
}

func TestStoreMatchMultipleRules(t *testing.T) {
	RegisterTestingT(t)

	store := NewStore()
	store.rules = []Rule{
		*NewRule(WithProto(6), WithDstPort(80)),   // Should not match
		*NewRule(WithProto(17), WithDstPort(53)),  // Should match
		*NewRule(WithProto(17), WithDstPort(443)), // Should not be reached
	}

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := store.Match(pkt)
	Expect(idx).To(Equal(1)) // Should match the second rule
	Expect(rule).ToNot(BeNil())
	Expect(*rule.DstPort).To(Equal(uint16(53)))
	Expect(*rule.Protocol).To(Equal(uint8(17)))
}

func TestStoreMatchNoMatch(t *testing.T) {
	RegisterTestingT(t)

	store := NewStore()
	store.rules = []Rule{
		*NewRule(WithProto(6), WithDstPort(80)),
		*NewRule(WithProto(6), WithDstPort(443)),
	}

	// Packet with protocol 17 won't match TCP rules
	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := store.Match(pkt)
	Expect(idx).To(Equal(-1))
	Expect(rule).To(BeNil())
}

func TestStoreMatchWithNetworks(t *testing.T) {
	RegisterTestingT(t)

	store := NewStore()
	store.rules = []Rule{
		*NewRule(WithSrcNet("192.168.0.0/16")), // Should not match
		*NewRule(WithSrcNet("10.10.0.0/16")),   // Should match
	}

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := store.Match(pkt)
	Expect(idx).To(Equal(1))
	Expect(rule).ToNot(BeNil())
	Expect(rule.SrcNet.String()).To(Equal("10.10.0.0/16"))
}

func TestStoreMatchIPv6(t *testing.T) {
	RegisterTestingT(t)

	store := NewStore()
	store.rules = []Rule{
		*NewRule(WithProto(6), WithSrcNet("dead:beef::/64")),
		*NewRule(WithDstNet("cafe::/112")),
	}

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("dead:beef::1"), traffic.WithSrcPort(44444), traffic.WithProto(6),
		traffic.WithDstAddr("cafe::1"), traffic.WithDstPort(80),
	)

	idx, rule := store.Match(pkt)
	Expect(idx).To(Equal(0)) // Should match the first rule
	Expect(rule).ToNot(BeNil())
	Expect(*rule.Protocol).To(Equal(uint8(6)))
	Expect(rule.SrcNet.String()).To(Equal("dead:beef::/64"))
}
