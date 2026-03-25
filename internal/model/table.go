package model

import (
	"fmt"
	"sort"

	"github.com/mazdakn/fwsim/internal/traffic"
	"github.com/sirupsen/logrus"
)

// Table holds a slice of firewall rules.
type Table struct {
	Name          string
	Rules         []*Rule
	DefaultAction *Rule
	logCtx        *logrus.Entry
}

func NewTable(name string, defaultAction Action) *Table {
	return &Table{
		Name: name,
		DefaultAction: NewRule(
			WithAction(defaultAction),
			WithName(fmt.Sprintf("table %s default action", name)),
		),
		logCtx: logrus.WithFields(logrus.Fields{
			"name":          name,
			"defaultAction": defaultAction,
		}),
	}
}

func (t *Table) AddRule(r *Rule) {
	i := sort.Search(len(t.Rules), func(i int) bool {
		return t.Rules[i].Order > r.Order
	})
	t.Rules = append(t.Rules, nil)
	copy(t.Rules[i+1:], t.Rules[i:])
	t.Rules[i] = r
}

func (t *Table) Match(pkt *traffic.Packet) Result {
	t.logCtx.Debugf("Matching packet %+v", pkt)
	var res Result
	for _, r := range t.Rules {
		res.Trace = append(res.Trace, r)
		if r.Match(pkt) {
			t.logCtx.Debugf("Rule %+v matched", r)
			res.Verdict = r.Action
			return res
		}
	}
	if t.DefaultAction == nil {
		t.logCtx.Warn("No rule matched and no default action is set")
		return res
	}
	t.logCtx.Debugf("No rule matched, using default action %s", t.DefaultAction.Action.String())
	t.DefaultAction.packetCount.Increment()
	res.Trace = append(res.Trace, t.DefaultAction)
	res.Verdict = t.DefaultAction.Action
	return res
}
