package table

import (
	"fmt"
	"sort"

	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/sirupsen/logrus"
)

// Table holds a slice of firewall rules.
type Table struct {
	Name          string
	Order         uint64
	Rules         []*rule.Rule
	DefaultAction *rule.Rule
	logCtx        *logrus.Entry
}

func New(name string, order uint64, defaultAction rule.Action) *Table {
	return &Table{
		Name:  name,
		Order: order,
		DefaultAction: rule.New(
			rule.WithAction(defaultAction),
			rule.WithName(fmt.Sprintf("table %s default action", name)),
		),
		logCtx: logrus.WithFields(logrus.Fields{
			"name":          name,
			"order":         order,
			"defaultAction": defaultAction,
		}),
	}
}

func (t *Table) AddRule(r *rule.Rule) {
	i := sort.Search(len(t.Rules), func(i int) bool {
		return t.Rules[i].Order > r.Order
	})
	t.Rules = append(t.Rules, nil)
	copy(t.Rules[i+1:], t.Rules[i:])
	t.Rules[i] = r
}

func (t *Table) Match(match *match.Match) rule.Action {
	t.logCtx.Debugf("Matching packet %+v", match.Packet)
	for _, r := range t.Rules {
		match.Result.Trace = append(match.Result.Trace, r)
		if r.Match(match.Packet) {
			t.logCtx.Debugf("Rule %+v matched", r)
			return r.Action
		}
	}
	if t.DefaultAction == nil {
		panic("No rule matched and no default action is set")
	}
	t.logCtx.Debugf("No rule matched, using default action %s", t.DefaultAction.Action.String())
	t.DefaultAction.IncrementPacketCount()
	match.Result.Trace = append(match.Result.Trace, t.DefaultAction)
	return t.DefaultAction.Action
}
