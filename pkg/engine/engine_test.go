package engine

import (
	"testing"

	"github.com/mazdakn/fwsim/internal/traffic"
	"github.com/mazdakn/fwsim/internal/model"
	. "github.com/onsi/gomega"
)

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	Expect(engine).ToNot(BeNil())
	Expect(engine.rules).To(BeEmpty())
}

func TestEngineMatchNoRules(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(-1))
	Expect(rule).To(BeNil())
}

func TestEngineMatchSingleRule(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.rules = []model.Rule{
		*model.NewRule(model.WithProto(17), model.WithDstPort(53)),
	}

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(0))
	Expect(rule).ToNot(BeNil())
	Expect(*rule.DstPort).To(Equal(uint16(53)))
	Expect(*rule.Protocol).To(Equal(uint8(17)))
}

func TestEngineMatchMultipleRules(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.rules = []model.Rule{
		*model.NewRule(model.WithProto(6), model.WithDstPort(80)),   // Should not match
		*model.NewRule(model.WithProto(17), model.WithDstPort(53)),  // Should match
		*model.NewRule(model.WithProto(17), model.WithDstPort(443)), // Should not be reached
	}

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(1)) // Should match the second rule
	Expect(rule).ToNot(BeNil())
	Expect(*rule.DstPort).To(Equal(uint16(53)))
	Expect(*rule.Protocol).To(Equal(uint8(17)))
}

func TestEngineMatchNoMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.rules = []model.Rule{
		*model.NewRule(model.WithProto(6), model.WithDstPort(80)),
		*model.NewRule(model.WithProto(6), model.WithDstPort(443)),
	}

	// Packet with protocol 17 won't match TCP rules
	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(-1))
	Expect(rule).To(BeNil())
}

func TestEngineMatchWithNetworks(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.rules = []model.Rule{
		*model.NewRule(model.WithSrcNet("192.168.0.0/16")), // Should not match
		*model.NewRule(model.WithSrcNet("10.10.0.0/16")),   // Should match
	}

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(1))
	Expect(rule).ToNot(BeNil())
	Expect(rule.SrcNet.String()).To(Equal("10.10.0.0/16"))
}

func TestEngineMatchIPv6(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.rules = []model.Rule{
		*model.NewRule(model.WithProto(6), model.WithSrcNet("dead:beef::/64")),
		*model.NewRule(model.WithDstNet("cafe::/112")),
	}

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("dead:beef::1"), traffic.WithSrcPort(44444), traffic.WithProto(6),
		traffic.WithDstAddr("cafe::1"), traffic.WithDstPort(80),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(0)) // Should match the first rule
	Expect(rule).ToNot(BeNil())
	Expect(*rule.Protocol).To(Equal(uint8(6)))
	Expect(rule.SrcNet.String()).To(Equal("dead:beef::/64"))
}
