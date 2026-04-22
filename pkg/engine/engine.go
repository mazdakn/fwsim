package engine

import (
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Resources struct {
	Sets    map[string]set.Set
	Table   *table.Table
	Packets []*packet.Packet
}

type Engine struct {
	table   *table.Table
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
	if resources.Table != nil {
		e.table = resources.Table
	}
	if resources.Packets != nil {
		e.matches = toMatches(resources.Packets)
	}
}

func (e *Engine) SetTable(t *table.Table) {
	e.table = t
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

func (e *Engine) Table() *table.Table {
	return e.table
}

func (e *Engine) RunTest(m *match.MatchContext) {
	e.table.Match(m)
}

func (e *Engine) RunTests() []*match.MatchContext {
	for _, m := range e.matches {
		e.table.Match(m)
	}
	return e.matches
}

func toMatches(pkts []*packet.Packet) []*match.MatchContext {
	matches := make([]*match.MatchContext, 0, len(pkts))
	for _, p := range pkts {
		matches = append(matches, &match.MatchContext{Packet: p})
	}
	return matches
}
