package engine

import (
	"fmt"

	runtimeengine "github.com/mazdakn/firecore/engine"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/fwsim/pkg/config"
)

type Engine struct {
	runtime *runtimeengine.Engine
	intents []*config.Intent
}

func New(r *config.Resource) *Engine {
	if r != nil {
		return &Engine{
			runtime: runtimeengine.New(r.Tables),
			intents: r.Intents,
		}
	}
	return &Engine{
		runtime: runtimeengine.New(nil),
		intents: []*config.Intent{},
	}
}

func (e *Engine) RunTests() []*match.MatchContext {
	contexts := make([]*match.MatchContext, 0, len(e.intents))
	for _, intent := range e.intents {
		mc, err := intent.ToMatchContext()
		if err != nil {
			// Intents stored in Resource are pre-validated; this indicates a
			// programming error.
			panic(fmt.Sprintf("engine.RunTests: failed to convert intent %q: %v", intent.Name, err))
		}
		contexts = append(contexts, mc)
	}
	return e.runtime.Run(contexts)
}
