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

	res := engine.Match(pkt)
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(res.EnforcedBy.Action).To(Equal(model.Drop))
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

	res := engine.Match(pkt)
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(*res.EnforcedBy.DstPort).To(Equal(uint16(53)))
	Expect(*res.EnforcedBy.Protocol).To(Equal(uint8(17)))
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

	res := engine.Match(pkt)
	Expect(res.EnforcedBy).ToNot(BeNil())
	// DstPort 53 uniquely identifies the second rule (first has DstPort 80, third has DstPort 443)
	Expect(*res.EnforcedBy.DstPort).To(Equal(uint16(53)))
	Expect(*res.EnforcedBy.Protocol).To(Equal(uint8(17)))
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

	res := engine.Match(pkt)
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(res.EnforcedBy.Action).To(Equal(model.Accept))
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

	res := engine.Match(pkt)
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(res.EnforcedBy.Action).To(Equal(model.Drop))
}

func TestEngineMatchDefaultActionNoRules(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	engine.table.DefaultAction = model.NewRule(model.WithAction(model.Accept))

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.10.10.1"), traffic.WithSrcPort(55555), traffic.WithProto(17),
		traffic.WithDstAddr("1.1.1.1"), traffic.WithDstPort(53),
	)

	res := engine.Match(pkt)
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(res.EnforcedBy.Action).To(Equal(model.Accept))
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

	res := engine.Match(pkt)
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(res.EnforcedBy.SrcNet.String()).To(Equal("10.10.0.0/16"))
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

	res := engine.Match(pkt)
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(*res.EnforcedBy.Protocol).To(Equal(uint8(6)))
	Expect(res.EnforcedBy.SrcNet.String()).To(Equal("dead:beef::/64"))
}

func TestPacketsFromFile(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	pkts, err := engine.PacketsFromFile("../../hack/packets.yaml")
	Expect(err).To(BeNil())
	Expect(len(pkts)).To(Equal(3))

	// Verify first packet
	Expect(pkts[0].SrcAddr.String()).To(Equal("192.168.1.5"))
	Expect(pkts[0].DstAddr.String()).To(Equal("1.1.1.1"))
	Expect(pkts[0].Protocol).To(Equal(uint8(7)))
	Expect(pkts[0].SrcPort).To(Equal(uint16(30000)))
	Expect(pkts[0].DstPort).To(Equal(uint16(80)))

	// Verify second packet
	Expect(pkts[1].SrcAddr.String()).To(Equal("10.0.0.1"))
	Expect(pkts[1].DstAddr.String()).To(Equal("2.2.2.2"))
	Expect(pkts[1].Protocol).To(Equal(uint8(7)))
	Expect(pkts[1].SrcPort).To(Equal(uint16(12345)))
	Expect(pkts[1].DstPort).To(Equal(uint16(8080)))
}

func TestPacketsFromFileMissing(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	pkts, err := engine.PacketsFromFile("nonexistent.yaml")
	Expect(err).ToNot(BeNil())
	Expect(pkts).To(BeNil())
}

func TestPacketsFromFileAndMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	err := engine.ConfigFromFile("../../hack/simple.yaml")
	Expect(err).To(BeNil())
	err = engine.LoadRules()
	Expect(err).To(BeNil())

	pkts, err := engine.PacketsFromFile("../../hack/packets.yaml")
	Expect(err).To(BeNil())
	Expect(len(pkts)).To(Equal(3))

	// First packet: src 192.168.1.5 -> dst 1.1.1.1:80 proto 7, src_port 30000 — matches rule 1 (Accept)
	res := engine.Match(pkts[0])
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(res.EnforcedBy.Action).To(Equal(model.Accept))

	// Second packet: src 10.0.0.1 -> dst 2.2.2.2:8080 proto 7 — matches rule 3 (Drop)
	res = engine.Match(pkts[1])
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(res.EnforcedBy.Action).To(Equal(model.Drop))

	// Third packet: proto 17, no matching rule — default action Drop
	res = engine.Match(pkts[2])
	Expect(res.EnforcedBy).ToNot(BeNil())
	Expect(res.EnforcedBy.Action).To(Equal(model.Drop))
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
