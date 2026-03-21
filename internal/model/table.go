package model

import (
	"github.com/mazdakn/fwsim/internal/traffic"
	"github.com/sirupsen/logrus"
)

// Table holds a slice of firewall rules.
type Table struct {
	Name          string
	Rules         []*Rule
	DefaultAction Action
	logCtx        *logrus.Entry
}

func NewTable(name string, defaultAction Action) *Table {
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

func (t *Table) Match(pkt *traffic.Packet) Result {
	t.logCtx.Debugf("Matching packet %+v", pkt)
	var res Result
	for _, r := range t.Rules {
		if r.Match(pkt) {
			t.logCtx.Debugf("Rule %+v matched", r)
			res.EnforcedBy = r
			return res
		} else {
			res.Trace = append(res.Trace, r)

		}
	}
	t.logCtx.Debugf("No rule matched, using default action %s", t.DefaultAction.String())
	return res

}
