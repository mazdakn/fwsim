package engine

import (
	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Engine struct {
	resources config.Resource
}

func New(r *config.Resource) *Engine {
	if r != nil {
		if r.Sets == nil {
			r.Sets = map[string]set.Set{}
		}
		return &Engine{resources: *r}
	}
	return &Engine{
		resources: config.Resource{
			Sets: map[string]set.Set{},
		},
	}
}

func (e *Engine) RegisterTable(t *table.Table) {
	e.resources.Tables = append(e.resources.Tables, t)
}

func (e *Engine) RegisterSet(name string, s set.Set) {
	e.resources.Sets[name] = s
}

// Sets returns the map of user-defined named sets loaded into the engine.
func (e *Engine) Sets() map[string]set.Set {
	return e.resources.Sets
}

func (e *Engine) Tables() []*table.Table {
	return e.resources.Tables
}

func (e *Engine) RunTests(matches []*match.MatchContext) []*match.MatchContext {
	for _, m := range matches {
		decided := false
		for _, t := range e.resources.Tables {
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
