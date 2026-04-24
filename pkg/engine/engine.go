package engine

import (
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Resources struct {
	Sets    map[string]set.Set
	Tables  []*table.Table
	Packets []*packet.Packet
	Intents []*match.MatchContext
}

type Engine struct {
	tables  []*table.Table
	matches []*match.MatchContext
	sets    map[string]set.Set
}

func New(resources ...Resources) *Engine {
	e := &Engine{
		matches: []*match.MatchContext{},
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
		e.SetTables(resources.Tables)
	}
	if resources.Packets != nil {
		e.matches = toMatches(resources.Packets)
	}
	if resources.Intents != nil {
		e.matches = resources.Intents
	}
}

func (e *Engine) SetTables(tables []*table.Table) {
	e.tables = tables
}

func (e *Engine) SetMatches(matches []*match.MatchContext) {
	e.matches = matches
}

func (e *Engine) SetSets(sets map[string]set.Set) {
	e.sets = sets
}

// Sets returns the map of user-defined named sets loaded into the engine.
func (e *Engine) Sets() map[string]set.Set {
	return e.sets
}

func (e *Engine) Tables() []*table.Table {
	return e.tables
}

func (e *Engine) RunTest(m *match.MatchContext) {
	for _, t := range e.tables {
		if t.Match(m) {
			return
		}
	}
	m.Verdict = match.NoMatch
}

func (e *Engine) RunTests() []*match.MatchContext {
	for _, m := range e.matches {
		e.RunTest(m)
	}
	return e.matches
}

func toMatches(pkts []*packet.Packet) []*match.MatchContext {
	matches := make([]*match.MatchContext, 0, len(pkts))
	for _, p := range pkts {
		matches = append(matches, match.New(p))
	}
	return matches
}
