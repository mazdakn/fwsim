package engine

import "github.com/mazdakn/fwsim/pkg/policy"

type Engine struct {
	input string

	store *policy.Store
}

func New(input string) *Engine {
	return &Engine{
		input: input,
		store: policy.NewStore(),
	}
}

func (e *Engine) Validate() {
}
