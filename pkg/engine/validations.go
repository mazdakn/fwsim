package engine

import (
	"fmt"
)

func (e *Engine) Validate() []string {
	return e.validateAllRulesUsed()
}

func (e *Engine) validateAllRulesUsed() (o []string) {
	for i, r := range e.table.Rules {
		if r.PacketCount() == 0 {
			o = append(o, fmt.Sprintf("Rule %d not used", i))
		}
	}
	return
}
