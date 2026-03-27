package model

import (
	"testing"

	"github.com/mazdakn/fwsim/internal/model/packet"
	. "github.com/onsi/gomega"
)

func TestTableAddRuleSortAscending(t *testing.T) {
	RegisterTestingT(t)

	table := NewTable("test", Drop)

	// Add rules with different orders
	rule1 := NewRule(WithName("rule1"), WithOrder(10), WithAction(Accept))
	rule2 := NewRule(WithName("rule2"), WithOrder(30), WithAction(Accept))
	rule3 := NewRule(WithName("rule3"), WithOrder(20), WithAction(Accept))

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

	table := NewTable("test", Drop)

	// Add rules with the same order (default 0)
	rule1 := NewRule(WithName("rule1"), WithAction(Accept))
	rule2 := NewRule(WithName("rule2"), WithAction(Drop))
	rule3 := NewRule(WithName("rule3"), WithAction(Accept))

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

	table := NewTable("test", Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// Add a high-order rule that drops traffic and a low-order rule that accepts it
	// After sorting ascending, the low-order Accept rule should match first
	highOrderDrop := NewRule(WithName("high-drop"), WithOrder(100), WithAction(Drop),
		WithProto(6), WithDstPort(80))
	lowOrderAccept := NewRule(WithName("low-accept"), WithOrder(1), WithAction(Accept),
		WithProto(6), WithDstPort(80))

	table.AddRule(highOrderDrop)
	table.AddRule(lowOrderAccept)

	res := table.Match(pkt)
	Expect(res.Verdict).To(Equal(Accept))
}
