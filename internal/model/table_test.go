package model

import (
	"testing"

	"github.com/mazdakn/fwsim/internal/traffic"
	. "github.com/onsi/gomega"
)

func TestTableAddRuleSortDescending(t *testing.T) {
	RegisterTestingT(t)

	table := NewTable("test", Drop)

	// Add rules with different orders
	rule1 := NewRule(WithName("rule1"), WithOrder(10), WithAction(Accept))
	rule2 := NewRule(WithName("rule2"), WithOrder(30), WithAction(Accept))
	rule3 := NewRule(WithName("rule3"), WithOrder(20), WithAction(Accept))

	table.AddRule(rule1)
	table.AddRule(rule2)
	table.AddRule(rule3)

	// Rules should be sorted in descending order by Order field
	Expect(table.Rules).To(HaveLen(3))
	Expect(table.Rules[0].Order).To(Equal(uint64(30)))
	Expect(table.Rules[1].Order).To(Equal(uint64(20)))
	Expect(table.Rules[2].Order).To(Equal(uint64(10)))
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

func TestTableMatchUsesDescendingOrder(t *testing.T) {
	RegisterTestingT(t)

	table := NewTable("test", Drop)

	pkt := traffic.NewPacket(
		traffic.WithSrcAddr("10.0.0.1"),
		traffic.WithDstAddr("1.1.1.1"),
		traffic.WithProto(6),
		traffic.WithDstPort(80),
	)

	// Add a low-order rule that drops traffic first, then a high-order rule that accepts it
	// After sorting descending, the high-order Accept rule should match first
	lowOrderDrop := NewRule(WithName("low-drop"), WithOrder(1), WithAction(Drop),
		WithProto(6), WithDstPort(80))
	highOrderAccept := NewRule(WithName("high-accept"), WithOrder(100), WithAction(Accept),
		WithProto(6), WithDstPort(80))

	table.AddRule(lowOrderDrop)
	table.AddRule(highOrderAccept)

	res := table.Match(pkt)
	Expect(res.Verdict).To(Equal(Accept))
}
