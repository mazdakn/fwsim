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

func (e *Engine) LoadRules(path string) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	rules, err := cfg.ToPolicyRules()
	if err != nil {
		return err
	}
	for _, r := range rules {
		e.store.AddRule(r)
	}
	return nil
}
