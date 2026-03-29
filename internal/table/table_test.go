package table

import (
	"testing"

	model "github.com/mazdakn/fwsim/internal"
	"github.com/mazdakn/fwsim/internal/packet"
	. "github.com/onsi/gomega"
)

func TestTableAddRuleSortAscending(t *testing.T) {
	RegisterTestingT(t)

	table := NewTable("test", model.Drop)

	// Add rules with different orders
	rule1 := model.NewRule(model.WithName("rule1"), model.WithOrder(10), model.WithAction(model.Accept))
	rule2 := model.NewRule(model.WithName("rule2"), model.WithOrder(30), model.WithAction(model.Accept))
	rule3 := model.NewRule(model.WithName("rule3"), model.WithOrder(20), model.WithAction(model.Accept))

	table.AddRule(rule1)
	table.AddRule(rule2)
	table.AddRule(rule3)

	// Rules should be sorted in ascending order by Order field
	Expect(table.Rules).To(HaveLen(3))
	Expect(table.Rules[0].Order).To(Equal(uint64(10)))
	Expect(table.Rules[1].Order).To(Equal(uint64(20)))
	Expect(table.Rules[2].Order).To(Equal(uint64(30)))
}

func TestTableAddRuleSortStableForEqualOrders(t *testing.T) {
	RegisterTestingT(t)

	table := NewTable("test", model.Drop)

	// Add rules with the same order (default 0)
	rule1 := model.NewRule(model.WithName("rule1"), model.WithAction(model.Accept))
	rule2 := model.NewRule(model.WithName("rule2"), model.WithAction(model.Drop))
	rule3 := model.NewRule(model.WithName("rule3"), model.WithAction(model.Accept))

	table.AddRule(rule1)
	table.AddRule(rule2)
	table.AddRule(rule3)

	// Rules with equal Order values should preserve insertion order (stable sort)
	Expect(table.Rules).To(HaveLen(3))
	Expect(table.Rules[0].Name).To(Equal("rule1"))
	Expect(table.Rules[1].Name).To(Equal("rule2"))
	Expect(table.Rules[2].Name).To(Equal("rule3"))
}

func TestTableMatchUsesAscendingOrder(t *testing.T) {
	RegisterTestingT(t)

	table := NewTable("test", model.Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// Add a high-order rule that drops traffic and a low-order rule that accepts it
	// After sorting ascending, the low-order Accept rule should match first
	highOrderDrop := model.NewRule(model.WithName("high-drop"), model.WithOrder(100), model.WithAction(model.Drop),
		model.WithProto(6), model.WithDstPort(80))
	lowOrderAccept := model.NewRule(model.WithName("low-accept"), model.WithOrder(1), model.WithAction(model.Accept),
		model.WithProto(6), model.WithDstPort(80))

	table.AddRule(highOrderDrop)
	table.AddRule(lowOrderAccept)

	res := table.Match(pkt)
	Expect(res.Verdict).To(Equal(model.Accept))
}
