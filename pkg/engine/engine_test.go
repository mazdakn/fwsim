package engine

import (
	"testing"

	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/traffic"
	. "github.com/onsi/gomega"
)

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	Expect(engine).ToNot(BeNil())
	Expect(engine.table.Rules).To(BeEmpty())
}

func TestEngineMatchNoRules(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.table.DefaultAction = model.NewRule(model.WithAction(model.Drop))
	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(-1))
	Expect(rule).ToNot(BeNil())
	Expect(rule.Action).To(Equal(model.Drop))
}

func TestEngineMatchSingleRule(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.table.Rules = []*model.Rule{
		model.NewRule(model.WithProto(17), model.WithDstPort(53)),
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
	engine.table.Rules = []*model.Rule{
		model.NewRule(model.WithProto(6), model.WithDstPort(80)),   // Should not match
		model.NewRule(model.WithProto(17), model.WithDstPort(53)),  // Should match
		model.NewRule(model.WithProto(17), model.WithDstPort(443)), // Should not be reached
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
	engine.table.Rules = []*model.Rule{
		model.NewRule(model.WithProto(6), model.WithDstPort(80)),
		model.NewRule(model.WithProto(6), model.WithDstPort(443)),
	}
	engine.table.DefaultAction = model.NewRule(model.WithAction(model.Accept))

	// Packet with protocol 17 won't match TCP rules, should use default action
	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(-1))
	Expect(rule).ToNot(BeNil())
	Expect(rule.Action).To(Equal(model.Accept))
}

func TestEngineMatchDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.table.Rules = []*model.Rule{
		model.NewRule(model.WithProto(6), model.WithDstPort(80)),
	}
	engine.table.DefaultAction = model.NewRule(model.WithAction(model.Drop))

	// Packet with protocol 17 will not match TCP rules, should use default action
	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(-1))
	Expect(rule).ToNot(BeNil())
	Expect(rule.Action).To(Equal(model.Drop))
}

func TestEngineMatchDefaultActionNoRules(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.table.DefaultAction = model.NewRule(model.WithAction(model.Accept))

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	idx, rule := engine.Match(pkt)
	Expect(idx).To(Equal(-1))
	Expect(rule).ToNot(BeNil())
	Expect(rule.Action).To(Equal(model.Accept))
}

func TestEngineMatchWithNetworks(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.table.Rules = []*model.Rule{
		model.NewRule(model.WithSrcNet("192.168.0.0/16")), // Should not match
		model.NewRule(model.WithSrcNet("10.10.0.0/16")),   // Should match
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
	engine.table.Rules = []*model.Rule{
		model.NewRule(model.WithProto(6), model.WithSrcNet("dead:beef::/64")),
		model.NewRule(model.WithDstNet("cafe::/112")),
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

func TestLoadRulesFromConfig(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	err := engine.ConfigFromFile("../../hack/simple.yaml")
	Expect(err).To(BeNil())

	err = engine.LoadRules()
	Expect(err).To(BeNil())
	Expect(len(engine.table.Rules)).To(Equal(3))

	// Verify first rule
	rule1 := engine.table.Rules[0]
	Expect(rule1.SrcNet).ToNot(BeNil())
	Expect(rule1.SrcNet.String()).To(Equal("192.168.1.0/24"))
	Expect(rule1.DstNet).ToNot(BeNil())
	Expect(rule1.DstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(rule1.Protocol).ToNot(BeNil())
	Expect(*rule1.Protocol).To(Equal(uint8(7)))
	Expect(rule1.Action.String()).To(Equal("Accept"))

	// Verify second rule
	rule2 := engine.table.Rules[1]
	Expect(rule2.DstNet).ToNot(BeNil())
	Expect(rule2.DstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(rule2.Protocol).ToNot(BeNil())
	Expect(*rule2.Protocol).To(Equal(uint8(7)))
	Expect(rule2.Action.String()).To(Equal("Drop"))

	// Verify default action is set
	Expect(engine.table.DefaultAction.Action.String()).To(Equal("Drop"))
}
