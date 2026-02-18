package engine

import "github.com/sirupsen/logrus"

func (e *Engine) Validate() {
	e.validateAllRulesUsed()
}

func (e *Engine) validateAllRulesUsed() {
	for i, r := range e.rules {
		if r.PacketCount() == 0 {
			logrus.Infof("Rule %v not used", i)
		}
	}
}
