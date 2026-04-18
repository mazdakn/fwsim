package engine

import (
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Engine struct {
	table   *table.Table
	matches []*match.Match
	sets    map[string]set.Set
}

func New() *Engine {
	return &Engine{
		sets: map[string]set.Set{},
	}
}

func (e *Engine) SetTable(t *table.Table) {
	e.table = t
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

func (e *Engine) RunTest(m *match.Match) {
	e.table.Match(m)
}

func (e *Engine) RunTests() []*match.Match {
	for _, m := range e.matches {
		e.table.Match(m)
	}
	return e.matches
}
