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

func NewTable(name string, defaultAction *Rule) *Table {
	return &Table{
		Name:          name,
		DefaultAction: defaultAction,
		logCtx: logrus.WithFields(logrus.Fields{
			"name":          name,
			"defaultAction": defaultAction,
		}),
	}
}

func (t *Table) AddRule(r *Rule) {
	t.Rules = append(t.Rules, r)
}

func (t *Table) Match(pkt *traffic.Packet) (int, *Rule) {
	t.logCtx.Debugf("Matching packet %+v", pkt)
	for i, r := range t.Rules {
		if r.Match(pkt) {
			t.logCtx.Debugf("Rule %+v matched", r)
			return i, r
		}
	}
	t.logCtx.Debugf("No rule matched, using default action %s", t.DefaultAction.Action.String())
	return -1, t.DefaultAction

}
