package engine

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	Expect(engine).ToNot(BeNil())
	Expect(engine.table.Rules).To(BeEmpty())
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
