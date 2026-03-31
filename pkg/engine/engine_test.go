package engine

import (
	"testing"

	"github.com/mazdakn/fwsim/internal/rule"
	. "github.com/onsi/gomega"
)

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	Expect(engine).ToNot(BeNil())
	Expect(engine.table.Rules).To(BeEmpty())
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
	Expect(len(pkts)).To(Equal(5))

	// First packet: src 192.168.1.5 -> dst 1.1.1.1:80 proto 7, src_port 30000 — matches rule 1 (Accept)
	res := engine.Match(pkts[0])
	Expect(res.Verdict).To(Equal(rule.Accept))

	// Second packet: src 10.0.0.1 -> dst 2.2.2.2:8080 proto 7 — matches rule 3 (Drop)
	res = engine.Match(pkts[1])
	Expect(res.Verdict).To(Equal(rule.Drop))

	// Third packet: proto 17, no matching rule — default action Accept
	res = engine.Match(pkts[2])
	Expect(res.Verdict).To(Equal(rule.Accept))
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
	Expect(rule1.Proto).ToNot(BeNil())
	Expect(rule1.Proto.Match(7)).To(BeTrue())
	Expect(rule1.Action.String()).To(Equal("Accept"))

	// Verify second rule
	rule2 := engine.table.Rules[1]
	Expect(rule2.DstNet).ToNot(BeNil())
	Expect(rule2.DstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(rule2.Proto).ToNot(BeNil())
	Expect(rule2.Proto.Match(7)).To(BeTrue())
	Expect(rule2.Action.String()).To(Equal("Drop"))

	// Verify default action is set
	Expect(engine.table.DefaultAction.Action.String()).To(Equal("Accept"))
}
