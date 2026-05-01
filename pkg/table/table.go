package table

import (
	"fmt"
	"sort"

	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/sirupsen/logrus"
)

// Table holds chains of firewall rules. Rules are accessed only via chains;
// a Table must have at least one chain.
type Table struct {
	Name          string
	Order         uint64
	Chains        map[string]*Chain
	entryChain    string
	DefaultAction *rule.Rule
	logCtx        *logrus.Entry
}

func New(name string, order uint64, defaultAction rule.Action) *Table {
	return &Table{
		Name:   name,
		Order:  order,
		Chains: make(map[string]*Chain),
		DefaultAction: rule.New(
			rule.WithAction(defaultAction),
			rule.WithName(fmt.Sprintf("table %s default action", name)),
		),
		logCtx: logrus.WithFields(logrus.Fields{
			"name":          name,
			"defaultAction": defaultAction,
		}),
	}
}

// AddChain adds c to the table. The first chain added becomes the entry chain
// unless SetEntryChain is called explicitly.
func (t *Table) AddChain(c *Chain) {
	t.Chains[c.Name] = c
	if t.entryChain == "" {
		t.entryChain = c.Name
	}
}

// SetEntryChain designates the named chain as the entry point for packet
// evaluation.
func (t *Table) SetEntryChain(name string) {
	t.entryChain = name
}

func (t *Table) Match(mc *match.MatchContext) bool {
	t.logCtx.Debugf("Matching packet %+v", mc.Packet)
	entry, ok := t.Chains[t.entryChain]
	if ok {
		result := entry.match(mc, t.Chains)
		switch result {
		case chainDecided:
			t.logCtx.Debugf("Chain determined verdict %s", mc.Verdict)
			return true
		case chainPass:
			t.logCtx.Debugf("Chain pass action, continuing to next table")
			return false
		}
	}
	// chainContinue: entry chain fell through
	t.logCtx.Debugf("No rule matched, using default action %v", t.DefaultAction.Action)
	return t.MatchDefaultRule(mc)
}

func (t *Table) MatchDefaultRule(mc *match.MatchContext) bool {
	if t.DefaultAction != nil {
		t.DefaultAction.IncrementPacketCount()
		mc.Trace = append(mc.Trace, t.DefaultAction)
		if t.DefaultAction.Action.IsTerminal() {
			mc.Verdict = &t.DefaultAction.Action
			return true
		}
		return false
	}
	return false

}

func SortTables(tables []*Table) {
	sort.SliceStable(tables, func(i, j int) bool {
		return tables[i].Order < tables[j].Order
	})
}
