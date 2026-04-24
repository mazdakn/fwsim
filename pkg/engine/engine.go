package engine

import (
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Engine struct {
	tables []*table.Table
	sets   map[string]set.Set
}

func New() *Engine {
	return &Engine{
		sets: map[string]set.Set{},
	}
}

func (e *Engine) RegisterTable(t *table.Table) {
	e.tables = append(e.tables, t)
}

func (e *Engine) RegisterSet(name string, s set.Set) {
	e.sets[name] = s
}

// Sets returns the map of user-defined named sets loaded into the engine.
func (e *Engine) Sets() map[string]set.Set {
	return e.sets
}

func (e *Engine) Tables() []*table.Table {
	return e.tables
}

func (e *Engine) RunTests(matches []*match.MatchContext) []*match.MatchContext {
	for _, m := range matches {
		decided := false
		for _, t := range e.tables {
			if t.Match(m) {
				decided = true
				break
			}
		}
		if !decided {
			m.Verdict = nil
		}
	}
	return matches
}
