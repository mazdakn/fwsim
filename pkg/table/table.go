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
	Rules         []*rule.Rule
	DefaultAction *rule.Rule
	logCtx        *logrus.Entry
}

func New(name string, defaultAction rule.Action) *Table {
	return &Table{
		Name: name,
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

func (t *Table) AddRule(r *rule.Rule) {
	i := sort.Search(len(t.Rules), func(i int) bool {
		return t.Rules[i].Order > r.Order
	})
	t.Rules = append(t.Rules, nil)
	copy(t.Rules[i+1:], t.Rules[i:])
	t.Rules[i] = r
}

func (t *Table) Match(matchContext *match.MatchContext) {
	t.logCtx.Debugf("Matching packet %+v", matchContext.Packet)
	for _, r := range t.Rules {
		matchContext.Trace = append(matchContext.Trace, r)
		if r.Match(matchContext.Packet) {
			t.logCtx.Debugf("Rule %+v matched", r)
			if r.Action == rule.Pass {
				t.logCtx.Debugf("Rule %+v action is Pass, continuing evaluation", r)
				continue
			}
			matchContext.Verdict = match.VerdictFromAction(r.Action)
			return
		}
	}
	if t.DefaultAction == nil {
		panic("No rule matched and no default action is set")
	}
	t.logCtx.Debugf("No rule matched, using default action %s", t.DefaultAction.Action.String())
	t.DefaultAction.IncrementPacketCount()
	matchContext.Trace = append(matchContext.Trace, t.DefaultAction)
	if t.DefaultAction.Action == rule.Pass {
		matchContext.Verdict = match.NoMatch
		return
	}
	matchContext.Verdict = match.VerdictFromAction(t.DefaultAction.Action)
}
