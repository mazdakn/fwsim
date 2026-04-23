package table

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
	. "github.com/onsi/gomega"
)

func TestTableAddRuleSortAscending(t *testing.T) {
	RegisterTestingT(t)

	table := New("test", rule.Drop)

	// Add rules with different orders
	rule1 := rule.New(rule.WithName("rule1"), rule.WithOrder(10), rule.WithAction(rule.Accept))
	rule2 := rule.New(rule.WithName("rule2"), rule.WithOrder(30), rule.WithAction(rule.Accept))
	rule3 := rule.New(rule.WithName("rule3"), rule.WithOrder(20), rule.WithAction(rule.Accept))

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

	table := New("test", rule.Drop)

	// Add rules with the same order (default 0)
	rule1 := rule.New(rule.WithName("rule1"), rule.WithAction(rule.Accept))
	rule2 := rule.New(rule.WithName("rule2"), rule.WithAction(rule.Drop))
	rule3 := rule.New(rule.WithName("rule3"), rule.WithAction(rule.Accept))

	table.AddRule(rule1)
	table.AddRule(rule2)
	table.AddRule(rule3)

	// Rules with equal Order values should preserve insertion order (stable sort)
	Expect(table.Rules).To(HaveLen(3))
	Expect(table.Rules[0].Name).To(Equal("rule1"))
	Expect(table.Rules[1].Name).To(Equal("rule2"))
	Expect(table.Rules[2].Name).To(Equal("rule3"))
}

func TestSortTablesSortAscendingAndStable(t *testing.T) {
	RegisterTestingT(t)

	t1 := New("first", rule.Accept)
	t1.Order = 10
	t2 := New("second", rule.Accept)
	t2.Order = 0
	t3 := New("third", rule.Accept)
	t3.Order = 10
	t4 := New("fourth", rule.Accept)
	t4.Order = 5

	tables := []*Table{t1, t2, t3, t4}
	SortTables(tables)

	Expect(tables[0].Name).To(Equal("second"))
	Expect(tables[1].Name).To(Equal("fourth"))
	Expect(tables[2].Name).To(Equal("first"))
	Expect(tables[3].Name).To(Equal("third"))
}

func TestTableMatchUsesAscendingOrder(t *testing.T) {
	RegisterTestingT(t)

	table := New("test", rule.Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// Add a high-order rule that drops traffic and a low-order rule that accepts it
	// After sorting ascending, the low-order Accept rule should match first
	highOrderDrop := rule.New(rule.WithName("high-drop"), rule.WithOrder(100), rule.WithAction(rule.Drop),
		rule.WithProto(6), rule.WithDstPort(80))
	lowOrderAccept := rule.New(rule.WithName("low-accept"), rule.WithOrder(1), rule.WithAction(rule.Accept),
		rule.WithProto(6), rule.WithDstPort(80))

	table.AddRule(highOrderDrop)
	table.AddRule(lowOrderAccept)

	m := match.MatchContext{Packet: pkt}
	table.Match(&m)
	Expect(m.Verdict).To(Equal(match.Accept))
}

func TestTableMatchPassContinuesToNextTable(t *testing.T) {
	RegisterTestingT(t)

	table := New("test", rule.Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	passRule := rule.New(rule.WithName("pass-http"), rule.WithOrder(1), rule.WithAction(rule.Pass),
		rule.WithProto(6), rule.WithDstPort(80))
	table.AddRule(passRule)

	m := match.MatchContext{Packet: pkt}
	matched := table.Match(&m)

	Expect(matched).To(BeFalse())
	Expect(m.Verdict).To(Equal(match.Pass))
	Expect(m.Trace).To(HaveLen(1))
	Expect(m.Trace[0].Name).To(Equal("pass-http"))
}

func TestTableMatchPassRuleDoesNotEvaluateDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	table := New("test", rule.Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	passRule := rule.New(rule.WithName("pass-http"), rule.WithOrder(1), rule.WithAction(rule.Pass),
		rule.WithProto(6), rule.WithDstPort(80))

	table.AddRule(passRule)

	m := match.MatchContext{Packet: pkt}
	matched := table.Match(&m)

	Expect(matched).To(BeFalse())
	Expect(m.Verdict).To(Equal(match.Pass))
	Expect(m.Trace).To(HaveLen(1))
	Expect(m.Trace[0].Name).To(Equal("pass-http"))
}

func TestTableMatchNoRuleAndDefaultPassReturnsNoMatchVerdict(t *testing.T) {
	RegisterTestingT(t)

	table := New("test", rule.Pass)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	m := match.MatchContext{Packet: pkt}
	matched := table.Match(&m)

	Expect(matched).To(BeFalse())
	Expect(m.Verdict).To(Equal(match.Pass))
	Expect(m.Trace).To(HaveLen(1))
	Expect(m.Trace[0].Name).To(Equal("table test default action"))
	Expect(m.Trace[0].Action).To(Equal(rule.Pass))
}
