package engine

type Engine struct {
	input string
}

func New(input string) *Engine {
	return &Engine{
		input: input,
	}
}

func (e *Engine) Validate() {
}
