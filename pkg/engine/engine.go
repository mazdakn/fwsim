package engine

import (
	"fmt"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/conntrack"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
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

func (e *Engine) RunTests() []*match.MatchContext {
	results := make([]*match.MatchContext, 0, len(e.resources.Intents))
	tracker := conntrack.NewTracker()
	for _, intent := range e.resources.Intents {
		mc, err := intent.ToMatchContext()
		if err != nil {
			// Intents stored in Resource are pre-validated; this indicates a
			// programming error.
			panic(fmt.Sprintf("engine.RunTests: failed to convert intent %q: %v", intent.Name, err))
		}
		mc.ConnState = tracker.Lookup(mc.Packet)
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
		if mc.Verdict != nil && *mc.Verdict == rule.Accept {
			tracker.CommitAccepted(mc.Packet)
		}
		results = append(results, mc)
	}
	return results
}
