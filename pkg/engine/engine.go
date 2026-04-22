package engine

import (
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Resources struct {
	Sets    map[string]set.Set
	Tables  []*table.Table
	Packets []*packet.Packet
}

type Engine struct {
	tables  []*table.Table
	matches []*match.Match
	sets    map[string]set.Set
}

func New(resources ...Resources) *Engine {
	e := &Engine{
		matches: []*match.Match{},
		sets:    map[string]set.Set{},
	}
	for _, resource := range resources {
		e.LoadResources(resource)
	}
	return e
}

func (e *Engine) LoadResources(resources Resources) {
	if resources.Sets != nil {
		e.sets = resources.Sets
	}
	if resources.Tables != nil {
		e.tables = resources.Tables
	}
	if resources.Packets != nil {
		e.matches = toMatches(resources.Packets)
	}
}

func (e *Engine) SetTable(t *table.Table) {
	e.tables = []*table.Table{t}
}

func (e *Engine) SetTables(tables []*table.Table) {
	e.tables = tables
}

func (e *Engine) SetMatches(matches []*match.Match) {
	e.matches = matches
}

func (e *Engine) SetSets(sets map[string]set.Set) {
	e.sets = sets
}

// Sets returns the map of user-defined named sets loaded into the engine.
func (e *Engine) Sets() map[string]set.Set {
	return e.sets
}

func (e *Engine) Table() *table.Table {
	if len(e.tables) == 0 {
		return nil
	}
	return e.tables[0]
}

func (e *Engine) Tables() []*table.Table {
	return e.tables
}

func (e *Engine) RunTest(m *match.Match) {
	for _, tbl := range e.tables {
		action := tbl.Match(m)
		if action == rule.Pass {
			continue
		}
		m.Result.Verdict = action
		return
	}
	m.Result.Verdict = rule.Pass
}

func (e *Engine) RunTests() []*match.Match {
	for _, m := range e.matches {
		e.RunTest(m)
	}
	return e.matches
}

func toMatches(pkts []*packet.Packet) []*match.Match {
	matches := make([]*match.Match, 0, len(pkts))
	for _, p := range pkts {
		matches = append(matches, &match.Match{Packet: p})
	}
	return matches
}
