package engine

import (
	"fmt"

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

func (e *Engine) RegisterIntent(i *config.Intent) {
	e.resources.Intents = append(e.resources.Intents, i)
}

func (e *Engine) RunTests() []*match.MatchContext {
	results := make([]*match.MatchContext, 0, len(e.resources.Intents))
	for _, intent := range e.resources.Intents {
		mc, err := intent.ToMatchContext()
		if err != nil {
			// Intents stored in Resource are pre-validated; this indicates a
			// programming error.
			panic(fmt.Sprintf("engine.RunTests: failed to convert intent %q: %v", intent.Name, err))
		}
		decided := false
		for _, t := range e.resources.Tables {
			if t.Match(mc) {
				decided = true
				break
			}
		}
		if !decided {
			mc.Verdict = nil
		}
		results = append(results, mc)
	}
	return results
}
