package model

import (
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
		Name:          name,
		DefaultAction: NewRule(WithAction(defaultAction)),
		logCtx: logrus.WithFields(logrus.Fields{
			"name":          name,
			"defaultAction": defaultAction,
		}),
	}
}

func (t *Table) AddRule(r *Rule) {
	t.Rules = append(t.Rules, r)
}

func (t *Table) Match(pkt *traffic.Packet) Result {
	t.logCtx.Debugf("Matching packet %+v", pkt)
	var res Result
	for _, r := range t.Rules {
		if r.Match(pkt) {
			t.logCtx.Debugf("Rule %+v matched", r)
			res.EnforcedBy = r
			return res
		}
		res.Trace = append(res.Trace, r)
	}
	if t.DefaultAction == nil {
		t.logCtx.Warn("No rule matched and no default action is set")
		return res
	}
	t.logCtx.Debugf("No rule matched, using default action %s", t.DefaultAction.Action.String())
	res.EnforcedBy = t.DefaultAction
	return res
}
