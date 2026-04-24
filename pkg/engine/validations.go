package engine

import (
	"fmt"
)

func (e *Engine) Validate() []string {
	return e.validateAllRulesUsed()
}

func (e *Engine) validateAllRulesUsed() (o []string) {
	for _, t := range e.resources.Tables {
		for i, r := range t.Rules {
			if r.PacketCount() == 0 {
				o = append(o, fmt.Sprintf("Table %s Rule %d not used", t.Name, i))
			}
		}
	}
	return
}
