package engine

import (
	"fmt"
)

func (e *Engine) Validate() []string {
	return e.validateAllRulesUsed()
}

func (e *Engine) validateAllRulesUsed() (o []string) {
	for tableIdx, tbl := range e.tables {
		for ruleIdx, r := range tbl.Rules {
			if r.PacketCount() == 0 {
				o = append(o, fmt.Sprintf("Table %d Rule %d not used", tableIdx, ruleIdx))
			}
		}
	}
	return
}
