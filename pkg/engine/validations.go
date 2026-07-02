package engine

func (e *Engine) Validate() []string {
	return e.runtime.Validate()
}
