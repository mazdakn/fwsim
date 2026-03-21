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
	for _, r := range t.Rules {
		if r.Match(pkt) {
			t.logCtx.Debugf("Rule %+v matched", r)
			return Result{EnforcedBy: r}
		}
	}
	if t.DefaultAction == nil {
		t.logCtx.Warn("No rule matched and no default action is set")
		return Result{}
	}
	t.logCtx.Debugf("No rule matched, using default action %s", t.DefaultAction.Action.String())
	return Result{EnforcedBy: t.DefaultAction}
}
