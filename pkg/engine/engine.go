package engine

import (
	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

type Engine struct {
	conf config.Config
}

func New(conf config.Config) *Engine {
	// Copy the sets map so the Engine owns its state independently of the caller's Config.
	sets := make(map[string]set.Set, len(conf.Sets))
	for k, v := range conf.Sets {
		sets[k] = v
	}
	conf.Sets = sets
	return &Engine{conf: conf}
}

func (e *Engine) RegisterTable(t *table.Table) {
	e.conf.Tables = append(e.conf.Tables, t)
}

func (e *Engine) RegisterSet(name string, s set.Set) {
	e.conf.Sets[name] = s
}

// Sets returns the map of user-defined named sets loaded into the engine.
func (e *Engine) Sets() map[string]set.Set {
	return e.conf.Sets
}

func (e *Engine) Tables() []*table.Table {
	return e.conf.Tables
}

func (e *Engine) RunTests(matches []*match.MatchContext) []*match.MatchContext {
	for _, m := range matches {
		decided := false
		for _, t := range e.conf.Tables {
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
