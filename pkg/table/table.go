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

func (t *Table) Match(matchContext *match.MatchContext) bool {
	t.logCtx.Debugf("Matching packet %+v", matchContext.Packet)
	entry, ok := t.Chains[t.entryChain]
	if !ok {
		panic(fmt.Sprintf("table %s: entry chain %q not found", t.Name, t.entryChain))
	}
	result := entry.match(matchContext, t.Chains)
	switch result {
	case chainDecided:
		t.logCtx.Debugf("Chain determined verdict %s", matchContext.Verdict)
		return true
	case chainPass:
		t.logCtx.Debugf("Chain pass action, continuing to next table")
		return false
	default: // chainContinue: entry chain fell through
		if t.DefaultAction == nil {
			panic("No rule matched and no default action is set")
		}
		t.logCtx.Debugf("No rule matched, using default action %s", t.DefaultAction.Action.String())
		t.DefaultAction.IncrementPacketCount()
		matchContext.Trace = append(matchContext.Trace, t.DefaultAction)
		matchContext.Verdict = &t.DefaultAction.Action
		return t.DefaultAction.Action != rule.Pass
	}
}

func SortTables(tables []*Table) {
	sort.SliceStable(tables, func(i, j int) bool {
		return tables[i].Order < tables[j].Order
	})
}
