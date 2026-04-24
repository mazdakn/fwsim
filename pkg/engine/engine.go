package engine

import (
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Engine struct {
	tables  []*table.Table
	matches []*match.MatchContext
	sets    map[string]set.Set
}

func New() *Engine {
	return &Engine{
		sets: map[string]set.Set{},
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

func (e *Engine) Matches() []*match.MatchContext {
	return e.matches
}

func (e *Engine) RunTest(m *match.MatchContext) {
	for _, t := range e.tables {
		if t.Match(m) {
			return
		}
	}
	m.Verdict = nil
}

func (e *Engine) RunTests() []*match.MatchContext {
	for _, m := range e.matches {
		e.RunTest(m)
	}
	return e.matches
}
