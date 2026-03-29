package table

import (
	"fmt"
	"sort"

	model "github.com/mazdakn/fwsim/internal"
	"github.com/mazdakn/fwsim/internal/packet"
	"github.com/sirupsen/logrus"
)

// Table holds a slice of firewall rules.
type Table struct {
	Name          string
	Rules         []*model.Rule
	DefaultAction *model.Rule
	logCtx        *logrus.Entry
}

func NewTable(name string, defaultAction model.Action) *Table {
	return &Table{
		Name: name,
		DefaultAction: model.NewRule(
			model.WithAction(defaultAction),
			model.WithName(fmt.Sprintf("table %s default action", name)),
		),
		logCtx: logrus.WithFields(logrus.Fields{
			"name":          name,
			"defaultAction": defaultAction,
		}),
	}
}

func (t *Table) AddRule(r *model.Rule) {
	i := sort.Search(len(t.Rules), func(i int) bool {
		return t.Rules[i].Order > r.Order
	})
	t.Rules = append(t.Rules, nil)
	copy(t.Rules[i+1:], t.Rules[i:])
	t.Rules[i] = r
}

func (t *Table) Match(pkt *packet.Packet) model.Result {
	t.logCtx.Debugf("Matching packet %+v", pkt)
	var res model.Result
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
	t.DefaultAction.IncrementPacketCount()
	res.Trace = append(res.Trace, t.DefaultAction)
	res.Verdict = t.DefaultAction.Action
	return res
}
